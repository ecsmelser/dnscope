"""
This file defines the database models for DNScope using SQLAlchemy's ORM.
Each class in this file represents a table in the PostgreSQL database and
describes the structure of the data DNScope stores.

These models define:
- Domains that are being monitored
- DNS records associated with each domain
- Security scan results associated with individual DNS records

The models also define relationships between tables, allowing DNScope to
link domains to their DNS records and link DNS records to their validation
results. This structure enables DNScope to store DNS configuration data,
track security findings over time, and support continuous DNS monitoring.
"""



from sqlalchemy import String, Integer, ForeignKey, DateTime, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from datetime import datetime

from app.db import Base

#define Domain to map to "domains" postgres table
class Domain(Base):
    __tablename__ = "domains"

    id: Mapped[int] = mapped_column(Integer, primary_key=True) #define unique ID
    domain_name: Mapped[str] = mapped_column(String, unique=True, nullable=False) #define domain_name column
    created_at: Mapped[datetime] = mapped_column( 
        DateTime, default=datetime.utcnow
    )

     #creates a relationship between Domain and DNSRecords, showing that one domain has many DNSRecords
     #domain.dns_records, would get a list of records belonging to the domain
    dns_records = relationship("DNSRecord", back_populates="domain") #back_populates ties "domain" to the reverse relationship on DNSRecord

#define DNSRecord to map to "dns_records" postgres table
class DNSRecord(Base):
    __tablename__ = "dns_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    domain_id: Mapped[int] = mapped_column(  
        Integer, ForeignKey("domains.id"), nullable=False #declares that domain_id has to point to a row in "domains" postgres table
    )
    #domain_id stores the id of the domain that the record belongs to

    record_type: Mapped[str] = mapped_column(String, nullable=False) #stores recordtype (A, CNAME, TXT, MX)
    name: Mapped[str] = mapped_column(String, nullable=False) #stores the name of the record
    value: Mapped[str] = mapped_column(String, nullable=False) #stores the value of the record (a -> 203.0.113.10, cname -> example-hosting.com)
    ttl: Mapped[int] = mapped_column(Integer) #stores record TTL

    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow
    )

    domain = relationship("Domain", back_populates="dns_records") #defines reverse relationship back to Domain class
    #record.domain would return the parent domain object
    scan_results = relationship("ScanResult", back_populates="dns_record") #defines that a DNS record can have many scan results

#define ScanResult to map to "scan_results" postgres table
class ScanResult(Base):
    __tablename__ = "scan_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    dns_record_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("dns_records.id"), nullable=True #this ties a scan result to a specific DNS record
    )

    risk_type: Mapped[str] = mapped_column(String, nullable=False) #label for what the issue is (dangling_cname, takeover_possible, etc.)
    severity: Mapped[str] = mapped_column(String, nullable=False) #stores severity level
    validation_source: Mapped[str] = mapped_column(String, nullable=False) #stores where the validation result came from, such as nuclei

    evidence: Mapped[str] = mapped_column(Text) #evidence can be long so we store in Text, JSON from nuclei, error messages, or other vulnerability fingerprints
    detected_at: Mapped[datetime] = mapped_column( #this is the timestamp of when an issue was detected
        DateTime, default=datetime.utcnow
    )

    
    dns_record = relationship("DNSRecord", back_populates="scan_results") #reverse relationship form the scan result to the DNS record
    #scan.dns_record returns the applicable record