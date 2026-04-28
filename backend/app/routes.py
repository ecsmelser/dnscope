from datetime import datetime

from fastapi import APIRouter, HTTPException

from app.db import SessionLocal
from app.models import DNSRecord, Domain, ScanResult, ScanRun
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
    runs a nuclei scan against the stored domain url,
    records the scan run, and stores each finding in the scan_results table

    why this exists:
    - this is the core monitoring loop of dnscope
    - it connects stored domains to automated validation
    - it creates a historical scan record before saving findings
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

        # create a scan run before nuclei starts
        # this gives dnscope a durable record that a scan was attempted
        scan_run = ScanRun(
            domain_id=domain.id,
            target=nuclei_target,
            scanner="nuclei",
            status="running",
        )

        # commit now so postgres generates a scan_run id
        # scan results will use this id as their parent
        db.add(scan_run)
        db.commit()
        db.refresh(scan_run)

        # run nuclei against the full url
        nuclei_findings = run_nuclei_scan(nuclei_target)

        # keep track of how many findings get saved
        findings_saved = 0

        # save each nuclei finding into the scan_results table
        for finding in nuclei_findings:
            scan_result = ScanResult(
                scan_run_id=scan_run.id,
                dns_record_id=None,
                risk_type=finding.get("template-id", "unknown"),
                severity=finding.get("info", {}).get("severity", "unknown"),
                validation_source="nuclei",
                evidence=json_safe_dump(finding),
            )

            db.add(scan_result)
            findings_saved += 1

        # mark the scan run as completed after all findings are saved
        scan_run.status = "completed"
        scan_run.findings_count = findings_saved
        scan_run.completed_at = datetime.utcnow()

        # commit the scan results and final scan run state together
        db.commit()

        # return the matches in a compact readable format
        return {
            "message": "scan completed",
            "domain_id": domain_id,
            "domain_name": domain.domain_name,
            "scan_run_id": scan_run.id,
            "nuclei_target": nuclei_target,
            "findings_returned": len(nuclei_findings),
            "findings_saved": findings_saved,
            "nuclei_matches": [compact_finding(finding) for finding in nuclei_findings],
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
                "scan_run_id": result.scan_run_id,
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


@router.get("/scan-runs")
def get_scan_runs():
    # return all scan runs, newest first
    db = SessionLocal()

    try:
        # query every scan run so the dashboard can show scan history
        scan_runs = db.query(ScanRun).order_by(ScanRun.started_at.desc()).all()

        # convert orm objects into json-friendly dictionaries
        return [
            {
                "id": scan_run.id,
                "domain_id": scan_run.domain_id,
                "target": scan_run.target,
                "scanner": scan_run.scanner,
                "status": scan_run.status,
                "findings_count": scan_run.findings_count,
                "started_at": scan_run.started_at,
                "completed_at": scan_run.completed_at,
            }
            for scan_run in scan_runs
        ]

    finally:
        # always close the db session
        db.close()


@router.get("/scan-runs/{scan_run_id}")
def get_scan_run(scan_run_id: int):
    # return one scan run and all findings produced by that scan
    db = SessionLocal()

    try:
        # look up the scan run by id
        scan_run = db.query(ScanRun).filter(ScanRun.id == scan_run_id).first()

        # return a 404 if the scan run does not exist
        if not scan_run:
            raise HTTPException(status_code=404, detail="scan run not found")

        # return scan metadata plus its related findings
        return {
            "id": scan_run.id,
            "domain_id": scan_run.domain_id,
            "target": scan_run.target,
            "scanner": scan_run.scanner,
            "status": scan_run.status,
            "findings_count": scan_run.findings_count,
            "started_at": scan_run.started_at,
            "completed_at": scan_run.completed_at,
            "findings": [
                {
                    "id": result.id,
                    "dns_record_id": result.dns_record_id,
                    "risk_type": result.risk_type,
                    "severity": result.severity,
                    "validation_source": result.validation_source,
                    "evidence": result.evidence,
                    "detected_at": result.detected_at,
                }
                for result in scan_run.scan_results
            ],
        }

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