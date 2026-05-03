from datetime import datetime, timedelta

from fastapi import APIRouter, File, HTTPException, UploadFile

from app.db import SessionLocal
from app.models import DNSRecord, Domain, ScanResult, ScanRun
from app.services.nuclei_runner import run_nuclei_scan
from app.schemas import DNSZoneUpload, DomainCreate, DomainScheduleUpdate


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


@router.post("/domains")
def create_domain(domain_data: DomainCreate):
    # create a new monitored domain without relying on seed data
    db = SessionLocal()

    try:
        domain_name = normalize_domain_name(domain_data.domain_name)

        if not domain_name:
            raise HTTPException(status_code=400, detail="domain name is required")

        existing_domain = db.query(Domain).filter(Domain.domain_name == domain_name).first()

        if existing_domain:
            raise HTTPException(status_code=400, detail="domain already exists")

        domain = Domain(domain_name=domain_name)
        db.add(domain)
        db.commit()
        db.refresh(domain)

        return serialize_domain(domain)

    finally:
        db.close()


@router.post("/domains/{domain_id}/dns-records/upload")
def upload_dns_records(domain_id: int, upload: DNSZoneUpload):
    # parse pasted cloudflare bind-style dns export text and store supported records
    return store_dns_records_for_domain(domain_id, upload.zone_text)


@router.post("/domains/{domain_id}/dns-records/upload-file")
async def upload_dns_records_file(domain_id: int, dns_file: UploadFile = File(...)):
    # accept a cloudflare dns export file and store supported records
    file_bytes = await dns_file.read()

    try:
        zone_text = file_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="dns export must be a utf-8 text file")

    return store_dns_records_for_domain(domain_id, zone_text)



@router.get("/domains/{domain_id}/dns-records")
def get_dns_records(domain_id: int):
    # return dns records imported for one domain
    db = SessionLocal()

    try:
        domain = db.query(Domain).filter(Domain.id == domain_id).first()

        if not domain:
            raise HTTPException(status_code=404, detail="domain not found")

        records = (
            db.query(DNSRecord)
            .filter(DNSRecord.domain_id == domain_id)
            .order_by(DNSRecord.record_type, DNSRecord.name)
            .all()
        )

        return {
            "domain_id": domain.id,
            "domain_name": domain.domain_name,
            "records": [
                serialize_dns_record(record)
                for record in records
            ],
        }

    finally:
        db.close()


@router.get("/domains/{domain_id}/scan-candidates")
def get_scan_candidates(domain_id: int):
    # return dns records that should be scanned for takeover-style risk
    db = SessionLocal()

    try:
        domain = db.query(Domain).filter(Domain.id == domain_id).first()

        if not domain:
            raise HTTPException(status_code=404, detail="domain not found")

        cname_records = (
            db.query(DNSRecord)
            .filter(
                DNSRecord.domain_id == domain_id,
                DNSRecord.record_type == "CNAME",
            )
            .order_by(DNSRecord.name)
            .all()
        )

        return {
            "domain_id": domain.id,
            "domain_name": domain.domain_name,
            "candidates": [
                serialize_scan_candidate(record)
                for record in cname_records
            ],
        }

    finally:
        db.close()


@router.post("/domains/{domain_id}/scan-candidates")
def scan_candidates(domain_id: int):
    # run nuclei scans against cname-derived scan candidates for one domain
    db = SessionLocal()

    try:
        domain = db.query(Domain).filter(Domain.id == domain_id).first()

        if not domain:
            raise HTTPException(status_code=404, detail="domain not found")

        cname_records = (
            db.query(DNSRecord)
            .filter(
                DNSRecord.domain_id == domain_id,
                DNSRecord.record_type == "CNAME",
            )
            .order_by(DNSRecord.name)
            .all()
        )

        scan_runs = []
        total_findings_saved = 0

        for record in cname_records:
            scan_target = f"https://{record.name}"

            scan_run = ScanRun(
                domain_id=domain.id,
                target=scan_target,
                scanner="nuclei",
                status="running",
            )

            db.add(scan_run)
            db.commit()
            db.refresh(scan_run)

            scan_output = run_nuclei_scan(scan_target)
            nuclei_findings = scan_output["findings"]

            findings_saved = 0

            for finding in nuclei_findings:
                scan_result = ScanResult(
                    scan_run_id=scan_run.id,
                    dns_record_id=record.id,
                    risk_type=finding.get("template-id", "unknown"),
                    severity=finding.get("info", {}).get("severity", "unknown"),
                    validation_source="nuclei",
                    template_id=finding.get("template-id"),
                    finding_name=finding.get("info", {}).get("name"),
                    finding_type=finding.get("type"),
                    matched_at=finding.get("matched-at"),
                    matcher_name=finding.get("matcher-name"),
                    extracted_results=json_safe_dump(finding.get("extracted-results")),
                    evidence=json_safe_dump(finding),
                )

                db.add(scan_result)
                findings_saved += 1

            if scan_output["timed_out"] or scan_output["returncode"] not in (0,):
                scan_run.status = "failed"
                scan_run.error_message = scan_output["stderr"] or "nuclei scan failed"
            else:
                scan_run.status = "completed"
                scan_run.error_message = None

            scan_run.findings_count = findings_saved
            scan_run.completed_at = datetime.utcnow()

            db.commit()

            total_findings_saved += findings_saved

            scan_runs.append({
                "dns_record": serialize_dns_record(record),
                "scan_candidate": serialize_scan_candidate(record),
                "scan_run": serialize_scan_run(scan_run),
                "findings_saved": findings_saved,
                "scanner_returncode": scan_output["returncode"],
                "scanner_error": scan_run.error_message,
            })

        return {
            "domain_id": domain.id,
            "domain_name": domain.domain_name,
            "candidates_scanned": len(cname_records),
            "scan_runs_created": len(scan_runs),
            "findings_saved": total_findings_saved,
            "scan_runs": scan_runs,
        }

    finally:
        db.close()


@router.get("/domains/{domain_id}")
def get_domain(domain_id: int):
    # return one domain plus its latest scan summary
    db = SessionLocal()

    try:
        domain = db.query(Domain).filter(Domain.id == domain_id).first()

        if not domain:
            raise HTTPException(status_code=404, detail="domain not found")

        latest_scan = (
            db.query(ScanRun)
            .filter(ScanRun.domain_id == domain_id)
            .order_by(ScanRun.started_at.desc())
            .first()
        )

        return {
            **serialize_domain(domain),
            "latest_scan": serialize_scan_run(latest_scan) if latest_scan else None,
        }

    finally:
        db.close()

@router.patch("/domains/{domain_id}/schedule")
def update_domain_schedule(domain_id: int, schedule_data: DomainScheduleUpdate):
    # configure scheduled scan settings for one domain
    db = SessionLocal()

    try:
        domain = db.query(Domain).filter(Domain.id == domain_id).first()

        if not domain:
            raise HTTPException(status_code=404, detail="domain not found")

        if schedule_data.scan_interval_minutes < 1:
            raise HTTPException(status_code=400, detail="scan interval must be at least 1 minute")

        domain.scheduled_scans_enabled = schedule_data.scheduled_scans_enabled
        domain.scan_interval_minutes = schedule_data.scan_interval_minutes

        db.commit()
        db.refresh(domain)

        return serialize_domain(domain)

    finally:
        db.close()


@router.get("/scheduler/status")
def get_scheduler_status():
    # return which domains are enabled for scheduled scans and whether they are due
    db = SessionLocal()

    try:
        now = datetime.utcnow()
        domains = db.query(Domain).order_by(Domain.domain_name).all()

        return {
            "checked_at": now,
            "domains": [
                serialize_schedule_status(domain, now)
                for domain in domains
            ],
        }

    finally:
        db.close()


@router.post("/scheduler/run-due-scans")
def run_due_scheduled_scans():
    # manually trigger the same due-scan job used by the background scheduler
    return run_due_scheduled_scans_job()



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
        scan_output = run_nuclei_scan(nuclei_target)
        nuclei_findings = scan_output["findings"]

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
                template_id=finding.get("template-id"),
                finding_name=finding.get("info", {}).get("name"),
                finding_type=finding.get("type"),
                matched_at=finding.get("matched-at"),
                matcher_name=finding.get("matcher-name"),
                extracted_results=json_safe_dump(finding.get("extracted-results")),
                evidence=json_safe_dump(finding),
            )

            db.add(scan_result)
            findings_saved += 1

        # mark the scan run as completed after all findings are saved
        if scan_output["timed_out"] or scan_output["returncode"] not in (0,):
            scan_run.status = "failed"
            scan_run.error_message = scan_output["stderr"] or "nuclei scan failed"
        else:
            scan_run.status = "completed"
            scan_run.error_message = None

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
            "scan_status": scan_run.status,
            "scanner_error": scan_run.error_message,
            "scanner_returncode": scan_output["returncode"],
            "scanner_stdout_preview": scan_output.get("stdout_preview"),
            "scanner_stderr_preview": scan_output.get("stderr_preview"),
            "nuclei_target": nuclei_target,
            "findings_returned": len(nuclei_findings),
            "findings_saved": findings_saved,
            "nuclei_matches": [compact_finding(finding) for finding in nuclei_findings],
        }

    finally:
        # always close the db session
        db.close()


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
                "template_id": result.template_id,
                "finding_name": result.finding_name,
                "finding_type": result.finding_type,
                "matched_at": result.matched_at,
                "matcher_name": result.matcher_name,
                "extracted_results": result.extracted_results,
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
            "error_message": scan_run.error_message,
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
                    "template_id": result.template_id,
                    "finding_name": result.finding_name,
                    "finding_type": result.finding_type,
                    "matched_at": result.matched_at,
                    "matcher_name": result.matcher_name,
                    "extracted_results": result.extracted_results,
                }
                for result in scan_run.scan_results
            ],
        }

    finally:
        db.close()


@router.get("/domains/{domain_id}/scan-runs")
def get_domain_scan_runs(domain_id: int):
    # return scan history for one domain, newest first
    db = SessionLocal()

    try:
        # look up the domain first so we can return a clear 404 if needed
        domain = db.query(Domain).filter(Domain.id == domain_id).first()

        if not domain:
            raise HTTPException(status_code=404, detail="domain not found")

        # query scan runs for this domain only
        scan_runs = (
            db.query(ScanRun)
            .filter(ScanRun.domain_id == domain_id)
            .order_by(ScanRun.started_at.desc())
            .all()
        )

        return {
            "domain_id": domain.id,
            "domain_name": domain.domain_name,
            "scan_runs": [
                {
                    "id": scan_run.id,
                    "target": scan_run.target,
                    "scanner": scan_run.scanner,
                    "status": scan_run.status,
                    "error_message": scan_run.error_message,
                    "findings_count": scan_run.findings_count,
                    "started_at": scan_run.started_at,
                    "completed_at": scan_run.completed_at,
                }
                for scan_run in scan_runs
            ],
        }

    finally:
        db.close()


@router.get("/domains/{domain_id}/latest-scan")
def get_latest_domain_scan(domain_id: int):
    # return the newest scan for one domain with summary counts
    db = SessionLocal()

    try:
        # look up the domain first so we can return a clear 404 if needed
        domain = db.query(Domain).filter(Domain.id == domain_id).first()

        if not domain:
            raise HTTPException(status_code=404, detail="domain not found")

        # get the newest scan run for this domain
        latest_scan = (
            db.query(ScanRun)
            .filter(ScanRun.domain_id == domain_id)
            .order_by(ScanRun.started_at.desc())
            .first()
        )

        # return a useful empty state if the domain has never been scanned
        if not latest_scan:
            return {
                "domain_id": domain.id,
                "domain_name": domain.domain_name,
                "latest_scan": None,
                "severity_counts": {
                    "info": 0,
                    "low": 0,
                    "medium": 0,
                    "high": 0,
                    "critical": 0,
                    "unknown": 0,
                },
            }

        # start with known severity buckets so the dashboard gets stable keys
        severity_counts = {
            "info": 0,
            "low": 0,
            "medium": 0,
            "high": 0,
            "critical": 0,
            "unknown": 0,
        }

        # count findings by severity for this scan run
        for result in latest_scan.scan_results:
            severity = result.severity or "unknown"

            if severity not in severity_counts:
                severity_counts[severity] = 0

            severity_counts[severity] += 1

        return {
            "domain_id": domain.id,
            "domain_name": domain.domain_name,
            "latest_scan": serialize_scan_run(latest_scan),
            "severity_counts": severity_counts,
        }

    finally:
        db.close()


@router.get("/domains/{domain_id}/scan-diff")
def get_domain_scan_diff(domain_id: int):
    # compare the latest scan against the previous scan for one domain
    db = SessionLocal()

    try:
        # look up the domain first so we can return a clear 404 if needed
        domain = db.query(Domain).filter(Domain.id == domain_id).first()

        if not domain:
            raise HTTPException(status_code=404, detail="domain not found")

        # get the two newest scan runs for this domain
        scan_runs = (
            db.query(ScanRun)
            .filter(ScanRun.domain_id == domain_id)
            .order_by(ScanRun.started_at.desc())
            .limit(2)
            .all()
        )

        # a diff needs at least two scans to compare
        if len(scan_runs) < 2:
            return {
                "domain_id": domain.id,
                "domain_name": domain.domain_name,
                "latest_scan_id": scan_runs[0].id if scan_runs else None,
                "previous_scan_id": None,
                "message": "at least two scan runs are needed to calculate a diff",
                "summary": {
                    "new": 0,
                    "resolved": 0,
                    "persisting": 0,
                },
                "new_findings": [],
                "resolved_findings": [],
                "persisting_findings": [],
            }

        latest_scan = scan_runs[0]
        previous_scan = scan_runs[1]

        # build lookup maps for each scan
        # the comparison key is intentionally simple for now:
        # template id plus matched target gives us a stable enough finding identity
        latest_findings = {
            finding_identity(result): result
            for result in latest_scan.scan_results
        }

        previous_findings = {
            finding_identity(result): result
            for result in previous_scan.scan_results
        }

        # compare finding keys between the latest and previous scan
        latest_keys = set(latest_findings.keys())
        previous_keys = set(previous_findings.keys())

        new_keys = latest_keys - previous_keys
        resolved_keys = previous_keys - latest_keys
        persisting_keys = latest_keys & previous_keys

        return {
            "domain_id": domain.id,
            "domain_name": domain.domain_name,
            "latest_scan_id": latest_scan.id,
            "previous_scan_id": previous_scan.id,
            "summary": {
                "new": len(new_keys),
                "resolved": len(resolved_keys),
                "persisting": len(persisting_keys),
            },
            "new_findings": [
                serialize_scan_result(latest_findings[key])
                for key in sorted(new_keys)
            ],
            "resolved_findings": [
                serialize_scan_result(previous_findings[key])
                for key in sorted(resolved_keys)
            ],
            "persisting_findings": [
                serialize_scan_result(latest_findings[key])
                for key in sorted(persisting_keys)
            ],
        }

    finally:
        db.close()


@router.get("/dashboard/summary")
def get_dashboard_summary():
    # return high-level dashboard data for the monitoring overview
    db = SessionLocal()

    try:
        domains = db.query(Domain).all()
        recent_scan_runs = db.query(ScanRun).order_by(ScanRun.started_at.desc()).limit(5).all()

        severity_totals = {
            "info": 0,
            "low": 0,
            "medium": 0,
            "high": 0,
            "critical": 0,
            "unknown": 0,
        }

        latest_scans = []

        open_alert_results = []
        seen_alert_keys = set()

        for result in db.query(ScanResult).order_by(ScanResult.detected_at.desc()).all():
            if not is_open_alert(result):
                continue

            alert_key = open_alert_identity(result)

            if alert_key in seen_alert_keys:
                continue

            seen_alert_keys.add(alert_key)
            open_alert_results.append(result)


        for domain in domains:
            latest_scan = (
                db.query(ScanRun)
                .filter(ScanRun.domain_id == domain.id)
                .order_by(ScanRun.started_at.desc())
                .first()
            )

            latest_scans.append({
                "domain": serialize_domain(domain),
                "latest_scan": serialize_scan_run(latest_scan) if latest_scan else None,
            })

            if latest_scan:
                for result in latest_scan.scan_results:
                    severity = result.severity or "unknown"

                    if severity not in severity_totals:
                        severity_totals[severity] = 0

                    severity_totals[severity] += 1

        return {
            "totals": {
                "domains": db.query(Domain).count(),
                "scan_runs": db.query(ScanRun).count(),
                "failed_scan_runs": db.query(ScanRun).filter(ScanRun.status == "failed").count(),
                "findings": db.query(ScanResult).count(),
            },
            "severity_totals": severity_totals,
            "open_alert_count": len(open_alert_results),
            "open_alerts": [
                serialize_open_alert(db, result)
                for result in open_alert_results[:5]
            ],
            "latest_scans": latest_scans,
            "recent_scan_runs": [
                serialize_scan_run(scan_run)
                for scan_run in recent_scan_runs
            ],
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


def finding_identity(result):
    """
    builds a stable comparison key for a stored finding

    why this exists:
    - scan diffs need to decide whether two findings are the same issue
    - nuclei results can include lots of changing raw evidence
    - template id plus matched target is a simple first version of identity
    """
    template_id = result.template_id or result.risk_type or "unknown"
    matched_at = result.matched_at or "unknown"

    return f"{template_id}::{matched_at}"


def serialize_scan_result(result):
    # return a dashboard-friendly version of one stored scan result
    return {
        "id": result.id,
        "scan_run_id": result.scan_run_id,
        "dns_record_id": result.dns_record_id,
        "risk_type": result.risk_type,
        "severity": result.severity,
        "validation_source": result.validation_source,
        "template_id": result.template_id,
        "finding_name": result.finding_name,
        "finding_type": result.finding_type,
        "matched_at": result.matched_at,
        "matcher_name": result.matcher_name,
        "extracted_results": result.extracted_results,
        "evidence": result.evidence,
        "detected_at": result.detected_at,
    }


def is_open_alert(result):
    # treat takeover-style findings as open alerts until a review workflow exists
    alert_text = " ".join([
        result.finding_name or "",
        result.template_id or "",
        result.risk_type or "",
        result.matched_at or "",
        result.finding_type or "",
        result.matcher_name or "",
        result.evidence or "",
    ]).lower()

    alert_keywords = [
        "takeover",
        "unclaimed",
        "dangling",
        "github",
        "pages",
        "cname",
        "service disconnect",
    ]

    return any(keyword in alert_text for keyword in alert_keywords)

def open_alert_identity(result):
    # keep one alert per issue type on each dns record or target
    issue = result.template_id or result.risk_type or result.finding_name or "unknown"

    if result.dns_record_id:
        return f"dns-record::{result.dns_record_id}::issue::{issue}"

    target = result.matched_at or "unknown"

    if target != "unknown":
        return f"target::{target}::issue::{issue}"

    return f"scan-result::{result.id}"



def serialize_open_alert(db, result):
    # return enough context for the dashboard to point users toward the issue
    scan_run = db.query(ScanRun).filter(ScanRun.id == result.scan_run_id).first()
    domain = db.query(Domain).filter(Domain.id == scan_run.domain_id).first() if scan_run else None
    target = result.matched_at or (scan_run.target if scan_run else "unknown target")

    return {
        "id": result.id,
        "domain_id": domain.id if domain else None,
        "domain_name": domain.domain_name if domain else "unknown domain",
        "scan_run_id": result.scan_run_id,
        "target": target,
        "severity": result.severity or "unknown",
        "finding_name": result.finding_name or result.template_id or result.risk_type or "unknown finding",
        "template_id": result.template_id,
        "detected_at": result.detected_at,
    }


def normalize_domain_name(domain_name):
    # normalize simple user input into a domain-style value
    normalized = domain_name.strip().lower()
    normalized = normalized.replace("https://", "").replace("http://", "")
    normalized = normalized.split("/")[0]

    return normalized


def serialize_domain(domain):
    # return a consistent domain response shape
    return {
        "id": domain.id,
        "domain_name": domain.domain_name,
        "created_at": domain.created_at,
        "scheduled_scans_enabled": domain.scheduled_scans_enabled,
        "scan_interval_minutes": domain.scan_interval_minutes,
        "last_scheduled_scan_at": domain.last_scheduled_scan_at,
    }



def serialize_scan_run(scan_run):
    # return a consistent scan run response shape
    return {
        "id": scan_run.id,
        "domain_id": scan_run.domain_id,
        "target": scan_run.target,
        "scanner": scan_run.scanner,
        "status": scan_run.status,
        "error_message": scan_run.error_message,
        "findings_count": scan_run.findings_count,
        "started_at": scan_run.started_at,
        "completed_at": scan_run.completed_at,
    }


def parse_zone_records(zone_text):
    # parse useful records from a cloudflare bind-style zone export
    supported_record_types = {"A", "AAAA", "CNAME", "TXT", "MX"}
    parsed_records = []

    for raw_line in zone_text.splitlines():
        line = raw_line.strip()

        if not line or line.startswith(";"):
            continue

        # remove inline cloudflare comments such as cf_tags
        record_part = line.split(";", 1)[0].strip()
        parts = record_part.split()

        if len(parts) < 5:
            continue

        name = clean_dns_name(parts[0])
        ttl = parse_ttl(parts[1])
        dns_class = parts[2].upper()
        record_type = parts[3].upper()
        value = " ".join(parts[4:])

        if dns_class != "IN":
            continue

        if record_type not in supported_record_types:
            continue

        parsed_records.append({
            "name": name,
            "ttl": ttl,
            "record_type": record_type,
            "value": clean_dns_value(value, record_type),
        })

    return parsed_records


def parse_ttl(value):
    # safely parse ttl values from dns zone exports
    try:
        return int(value)
    except ValueError:
        return 0


def clean_dns_name(value):
    # remove trailing zone-file dot for display and matching
    return value.rstrip(".").lower()


def clean_dns_value(value, record_type):
    # normalize dns values while preserving txt record content
    if record_type == "TXT":
        return value.strip()

    return value.rstrip(".").lower()


def serialize_dns_record(record):
    # return a consistent dns record response shape
    return {
        "id": record.id,
        "domain_id": record.domain_id,
        "record_type": record.record_type,
        "name": record.name,
        "value": record.value,
        "ttl": record.ttl,
        "created_at": record.created_at,
    }


def serialize_scan_candidate(record):
    # turn a cname record into a url-level scan target
    return {
        "dns_record_id": record.id,
        "domain_id": record.domain_id,
        "record_type": record.record_type,
        "name": record.name,
        "value": record.value,
        "ttl": record.ttl,
        "scan_target": f"https://{record.name}",
    }


def store_dns_records_for_domain(domain_id, zone_text):
    # parse a cloudflare bind-style dns export and store supported records
    db = SessionLocal()

    try:
        domain = db.query(Domain).filter(Domain.id == domain_id).first()

        if not domain:
            raise HTTPException(status_code=404, detail="domain not found")

        parsed_records = parse_zone_records(zone_text)

        records_created = 0
        records_skipped = 0

        for record_data in parsed_records:
            existing_record = (
                db.query(DNSRecord)
                .filter(
                    DNSRecord.domain_id == domain_id,
                    DNSRecord.record_type == record_data["record_type"],
                    DNSRecord.name == record_data["name"],
                    DNSRecord.value == record_data["value"],
                )
                .first()
            )

            if existing_record:
                records_skipped += 1
                continue

            dns_record = DNSRecord(
                domain_id=domain_id,
                record_type=record_data["record_type"],
                name=record_data["name"],
                value=record_data["value"],
                ttl=record_data["ttl"],
            )

            db.add(dns_record)
            records_created += 1

        db.commit()

        return {
            "domain_id": domain.id,
            "domain_name": domain.domain_name,
            "records_found": len(parsed_records),
            "records_created": records_created,
            "records_skipped": records_skipped,
        }

    finally:
        db.close()



def serialize_schedule_status(domain, now):
    # return schedule state in a dashboard-friendly format
    due_at = None
    is_due = False

    if domain.scheduled_scans_enabled:
        if domain.last_scheduled_scan_at:
            due_at = domain.last_scheduled_scan_at + timedelta(minutes=domain.scan_interval_minutes)
            is_due = now >= due_at
        else:
            is_due = True

    return {
        "domain_id": domain.id,
        "domain_name": domain.domain_name,
        "scheduled_scans_enabled": domain.scheduled_scans_enabled,
        "scan_interval_minutes": domain.scan_interval_minutes,
        "last_scheduled_scan_at": domain.last_scheduled_scan_at,
        "next_scheduled_scan_at": due_at,
        "is_due": is_due,
    }


def domain_is_due_for_scan(domain, now):
    # decide whether a scheduled scan should run for this domain
    if not domain.scheduled_scans_enabled:
        return False

    if not domain.last_scheduled_scan_at:
        return True

    next_scan_at = domain.last_scheduled_scan_at + timedelta(minutes=domain.scan_interval_minutes)

    return now >= next_scan_at


def run_scheduled_scan_target(db, domain, target, dns_record=None):
    # run nuclei for one scheduled target and save the scan run plus findings
    scan_run = ScanRun(
        domain_id=domain.id,
        target=target,
        scanner="nuclei",
        status="running",
    )

    db.add(scan_run)
    db.commit()
    db.refresh(scan_run)

    scan_output = run_nuclei_scan(target)
    nuclei_findings = scan_output["findings"]

    findings_saved = 0

    for finding in nuclei_findings:
        scan_result = ScanResult(
            scan_run_id=scan_run.id,
            dns_record_id=dns_record.id if dns_record else None,
            risk_type=finding.get("template-id", "unknown"),
            severity=finding.get("info", {}).get("severity", "unknown"),
            validation_source="nuclei",
            template_id=finding.get("template-id"),
            finding_name=finding.get("info", {}).get("name"),
            finding_type=finding.get("type"),
            matched_at=finding.get("matched-at"),
            matcher_name=finding.get("matcher-name"),
            extracted_results=json_safe_dump(finding.get("extracted-results")),
            evidence=json_safe_dump(finding),
        )

        db.add(scan_result)
        findings_saved += 1

    if scan_output["timed_out"] or scan_output["returncode"] not in (0,):
        scan_run.status = "failed"
        scan_run.error_message = scan_output["stderr"] or "nuclei scan failed"
    else:
        scan_run.status = "completed"
        scan_run.error_message = None

    scan_run.findings_count = findings_saved
    scan_run.completed_at = datetime.utcnow()

    db.commit()
    db.refresh(scan_run)

    return {
        "scan_run": serialize_scan_run(scan_run),
        "dns_record": serialize_dns_record(dns_record) if dns_record else None,
        "findings_saved": findings_saved,
        "scanner_returncode": scan_output["returncode"],
        "scanner_error": scan_run.error_message,
    }


def run_due_scheduled_scans_job():
    # run scans for domains whose schedule is enabled and currently due
    db = SessionLocal()

    try:
        now = datetime.utcnow()
        domains = (
            db.query(Domain)
            .filter(Domain.scheduled_scans_enabled == True)
            .order_by(Domain.domain_name)
            .all()
        )

        scanned_domains = []
        skipped_domains = []

        for domain in domains:
            if not domain_is_due_for_scan(domain, now):
                skipped_domains.append(serialize_schedule_status(domain, now))
                continue

            cname_records = (
                db.query(DNSRecord)
                .filter(
                    DNSRecord.domain_id == domain.id,
                    DNSRecord.record_type == "CNAME",
                )
                .order_by(DNSRecord.name)
                .all()
            )

            scan_results = []

            if cname_records:
                for record in cname_records:
                    scan_results.append(
                        run_scheduled_scan_target(
                            db=db,
                            domain=domain,
                            target=f"https://{record.name}",
                            dns_record=record,
                        )
                    )
            else:
                scan_results.append(
                    run_scheduled_scan_target(
                        db=db,
                        domain=domain,
                        target=f"https://{domain.domain_name}",
                        dns_record=None,
                    )
                )

            domain.last_scheduled_scan_at = now
            db.commit()
            db.refresh(domain)

            scanned_domains.append({
                "domain": serialize_domain(domain),
                "scan_results": scan_results,
            })

        return {
            "checked_at": now,
            "domains_scanned": len(scanned_domains),
            "domains_skipped": len(skipped_domains),
            "scanned_domains": scanned_domains,
            "skipped_domains": skipped_domains,
        }

    finally:
        db.close()
