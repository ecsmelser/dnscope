"""
this file defines the database models for dnscope using sqlalchemy's orm.
each class in this file represents a table in the postgresql database and
describes the structure of the data dnscope stores.

these models define:
- domains that are being monitored
- dns records associated with each domain
- scan runs that represent one nuclei scan event
- security scan results associated with each scan run

the scan run table is important because dnscope is meant to track history
over time. instead of only storing individual findings, dnscope can now say
which findings came from which scan, when that scan started, when it finished,
and how many findings were returned.
"""

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base


# define domain to map to the "domains" postgres table
class Domain(Base):
    __tablename__ = "domains"

    # define unique id for each monitored domain
    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    # store the domain name, such as example.com
    domain_name: Mapped[str] = mapped_column(String, unique=True, nullable=False)

    # store when the domain was first added to dnscope
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow
    )

    # create a relationship between domain and dnsrecord
    # domain.dns_records returns a list of records belonging to the domain
    dns_records = relationship("DNSRecord", back_populates="domain")

    # create a relationship between domain and scanrun
    # domain.scan_runs returns the scan history for this domain
    scan_runs = relationship("ScanRun", back_populates="domain")


# define dnsrecord to map to the "dns_records" postgres table
class DNSRecord(Base):
    __tablename__ = "dns_records"

    # define unique id for each dns record
    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    # store which domain this dns record belongs to
    # this must point to an existing row in the domains table
    domain_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("domains.id"), nullable=False
    )

    # store record type, such as a, cname, txt, or mx
    record_type: Mapped[str] = mapped_column(String, nullable=False)

    # store the record name, such as example.com or app.example.com
    name: Mapped[str] = mapped_column(String, nullable=False)

    # store the record value, such as an ip address or cname target
    value: Mapped[str] = mapped_column(String, nullable=False)

    # store record ttl
    ttl: Mapped[int] = mapped_column(Integer)

    # store when the dns record was first added
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow
    )

    # define reverse relationship back to the parent domain
    # record.domain returns the domain this record belongs to
    domain = relationship("Domain", back_populates="dns_records")

    # define that a dns record can have many scan results
    # this is optional for now because current scans run against domain urls directly
    scan_results = relationship("ScanResult", back_populates="dns_record")


# define scanrun to map to the "scan_runs" postgres table
class ScanRun(Base):
    __tablename__ = "scan_runs"

    # define unique id for each scan event
    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    # store which domain was scanned
    # this lets dnscope show scan history per domain
    domain_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("domains.id"), nullable=False
    )

    # store the exact target sent to nuclei, such as https://example.com
    target: Mapped[str] = mapped_column(String, nullable=False)

    # store which scanner produced this run
    # this is nuclei for now, but this keeps the model flexible later
    scanner: Mapped[str] = mapped_column(String, nullable=False, default="nuclei")

    # store scan state, such as running, completed, or failed
    status: Mapped[str] = mapped_column(String, nullable=False, default="running")

    # store how many findings were saved for this scan run
    findings_count: Mapped[int] = mapped_column(Integer, default=0)

    # store when the scan started
    started_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow
    )

    # store when the scan completed
    # this is nullable because a scan may still be running or may fail early
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime, nullable=True
    )

    # define reverse relationship back to the scanned domain
    domain = relationship("Domain", back_populates="scan_runs")

    # define that one scan run can produce many scan results
    scan_results = relationship("ScanResult", back_populates="scan_run")


# define scanresult to map to the "scan_results" postgres table
class ScanResult(Base):
    __tablename__ = "scan_results"

    # define unique id for each finding
    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    # store which scan run produced this finding
    # this is what makes historical scan review possible
    scan_run_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("scan_runs.id"), nullable=False
    )

    # optionally tie a finding to a specific dns record
    # this is nullable because current nuclei scans run against the domain url
    dns_record_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("dns_records.id"), nullable=True
    )

    # store the issue label
    # for nuclei results, this currently uses the template id
    risk_type: Mapped[str] = mapped_column(String, nullable=False)

    # store severity level from the scanner
    severity: Mapped[str] = mapped_column(String, nullable=False)

    # store where the validation result came from, such as nuclei
    validation_source: Mapped[str] = mapped_column(String, nullable=False)

    # store the nuclei template id separately so dashboards do not need to parse evidence
    template_id: Mapped[str | None] = mapped_column(String, nullable=True)

    # store the readable finding name from nuclei
    finding_name: Mapped[str | None] = mapped_column(String, nullable=True)

    # store the nuclei result type, such as dns, http, or ssl
    finding_type: Mapped[str | None] = mapped_column(String, nullable=True)

    # store the exact target or value nuclei matched on
    matched_at: Mapped[str | None] = mapped_column(String, nullable=True)

    # store the matcher name when nuclei provides one
    matcher_name: Mapped[str | None] = mapped_column(String, nullable=True)

    # store extracted results as text because nuclei may return a list
    extracted_results: Mapped[str | None] = mapped_column(Text, nullable=True)


    # store raw evidence as text
    # nuclei findings are json dictionaries, so routes.py serializes them first
    evidence: Mapped[str] = mapped_column(Text)

    # store when this finding was detected
    detected_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow
    )

    # define reverse relationship back to the scan run
    # result.scan_run returns the scan event that produced this finding
    scan_run = relationship("ScanRun", back_populates="scan_results")

    # define reverse relationship back to the dns record when one is linked
    # result.dns_record returns the applicable record, or none for url-level scans
    dns_record = relationship("DNSRecord", back_populates="scan_results")
