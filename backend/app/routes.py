from fastapi import APIRouter, HTTPException
from app.db import SessionLocal
from app.models import Domain, DNSRecord, ScanResult
from app.services.nuclei_runner import run_nuclei_scan

router = APIRouter()


@router.get("/domains")
def get_domains():
    """
    returns all domains currently stored in the database

    why this exists:
    - lets us verify that seeded or ingested data is actually being stored
    - gives us a simple read endpoint for testing
    """
    db = SessionLocal()

    try:
        # query all rows from the domains table
        domains = db.query(Domain).all()

        # convert orm objects into simple dictionaries that fastapi can return as json
        return [
            {
                "id": domain.id,
                "domain_name": domain.domain_name,
                "created_at": domain.created_at,
            }
            for domain in domains
        ]

    finally:
        db.close()


@router.post("/seed")
def seed_data():
    """
    inserts a test domain and a couple of dns records into the database

    why this exists:
    - provides fake but realistic data for development
    - lets us test database writes without needing real dns provider integration yet
    """
    db = SessionLocal()

    try:
        # check whether the example domain already exists
        # this prevents duplicate seed attempts from crashing on the unique domain constraint
        existing_domain = db.query(Domain).filter(Domain.domain_name == "example.com").first()
        if existing_domain:
            return {
                "message": "seed data already exists",
                "domain_id": existing_domain.id
            }

        # create a test domain row
        domain = Domain(domain_name="example.com")
        db.add(domain)

        # commit so postgres writes the row and generates an id
        db.commit()

        # refresh pulls the generated id back into the python object
        db.refresh(domain)

        # create a cname record that could later be used to simulate takeover-related scanning
        record1 = DNSRecord(
            domain_id=domain.id,
            record_type="CNAME",
            name="example.com",
            value="unclaimed-app.herokuapp.com",
            ttl=300,
        )

        # create a normal a record for contrast
        record2 = DNSRecord(
            domain_id=domain.id,
            record_type="A",
            name="example.com",
            value="203.0.113.10",
            ttl=300,
        )

        # add both dns records in one go
        db.add_all([record1, record2])

        # commit the dns records to the database
        db.commit()

        return {
            "message": "seed data created",
            "domain_id": domain.id
        }

    finally:
        db.close()


@router.post("/scan/domain/{domain_id}")
def scan_domain(domain_id: int):
    """
    runs nuclei scans against all relevant dns records for a given domain
    and stores findings in the scan_results table

    why this exists:
    - this is the core monitoring loop of dnscope
    - it connects stored dns records to automated validation
    - it persists findings so they can later be queried and shown to users
    """
    db = SessionLocal()

    try:
        # look up the domain first
        domain = db.query(Domain).filter(Domain.id == domain_id).first()

        # if the domain does not exist, return a 404 error
        if not domain:
            raise HTTPException(status_code=404, detail="domain not found")

        # retrieve all dns records associated with this domain
        records = db.query(DNSRecord).filter(DNSRecord.domain_id == domain_id).all()

        # if the domain exists but has no records, return a clean response
        if not records:
            return {
                "message": "no dns records found for this domain",
                "domain_id": domain_id,
                "scanned_records": 0,
                "findings_saved": 0
            }

        # track how many records scanned
        scanned_records = 0

        # track how many findings were successfully saved
        findings_saved = 0

        # loop through all records for this domain
        for record in records:
            # these are the most relevant for subdomain takeover scenarios
            if record.record_type != "CNAME":
                continue

            scanned_records += 1

            # run nuclei against the record's hostname, not its target value
            #v.2 updated to append https:// before the record to format for Nuclei scan
            nuclei_target = f"https://{record.name}"
            nuclei_findings = run_nuclei_scan(nuclei_target)

            # for every finding nuclei returns, create a scanresult row
            for finding in nuclei_findings:
                scan_result = ScanResult(
                    dns_record_id=record.id,

                    # template-id is the nuclei template identifier
                    # we use it here as a rough risk type label
                    risk_type=finding.get("template-id", "unknown"),

                    # pull severity out of the nested "info" object if it exists
                    severity=finding.get("info", {}).get("severity", "unknown"),

                    # track that nuclei was the validation source
                    validation_source="nuclei",

                    # store the full finding as json text for now
                    evidence=json_safe_dump(finding)
                )

                db.add(scan_result)
                findings_saved += 1

        # save all created scan results in one transaction
        db.commit()

        return {
            "message": "scan completed",
            "domain_id": domain_id,
            "domain_name": domain.domain_name,
            "scanned_records": scanned_records,
            "findings_saved": findings_saved
        }

    finally:
        db.close()


def json_safe_dump(data):
    """
    converts a python dictionary into a json string for storage in the database

    why this exists:
    - scanresult.evidence expects text
    - nuclei findings come in as dictionaries
    - this gives us a safe way to store the full raw result
    """
    import json

    try:
        return json.dumps(data)
    except Exception:
        # fallback: if json conversion fails for any reason,
        # store a string version instead of crashing
        return str(data)