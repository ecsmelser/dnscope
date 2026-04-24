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
        # look up the domain row first
        domain = db.query(Domain).filter(Domain.id == domain_id).first()

        # return a 404 if the domain does not exist
        if not domain:
            raise HTTPException(status_code=404, detail="domain not found")

        # build the nuclei target from the stored domain name
        nuclei_target = f"https://{domain.domain_name}"

        # run nuclei against the full url
        nuclei_findings = run_nuclei_scan(nuclei_target)

        # return the matches in a compact readable format
        return {
            "message": "scan completed",
            "domain_id": domain_id,
            "domain_name": domain.domain_name,
            "nuclei_target": nuclei_target,
            "findings_returned": len(nuclei_findings),
            "nuclei_matches": [compact_finding(finding) for finding in nuclei_findings]
        }

    finally:
        # always close the db session
        db.close()

# test get to see results

@router.get("/scan-results")
def get_scan_results():
    # return all stored scan results from the database
    db = SessionLocal()

    try:
        # query every row from the scan_results table
        results = db.query(ScanResult).all()

        # convert the orm objects into json-friendly dictionaries
        return [
            {
                "id": result.id,
                "dns_record_id": result.dns_record_id,
                "risk_type": result.risk_type,
                "severity": result.severity,
                "validation_source": result.validation_source,
                "evidence": result.evidence,
                "detected_at": result.detected_at,
            }
            for result in results
        ]

    finally:
        # always close the db session
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


def compact_finding(finding):
    # return a cleaner, smaller version of a nuclei finding
    return {
        "template_id": finding.get("template-id"),
        "name": finding.get("info", {}).get("name"),
        "severity": finding.get("info", {}).get("severity"),
        "type": finding.get("type"),
        "matched_at": finding.get("matched-at"),
        "matcher": finding.get("matcher-name"),
        "extracted": finding.get("extracted-results"),
    }