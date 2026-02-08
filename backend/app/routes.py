from fastapi import APIRouter
from app.db import SessionLocal
from app.models import Domain, DNSRecord

router = APIRouter()


@router.post("/seed")
def seed_data():
    db = SessionLocal()

    try:
        #create a test domain
        domain = Domain(domain_name="example.com")
        db.add(domain)
        db.commit()
        db.refresh(domain)

        #create DNS records for the domain
        record1 = DNSRecord(
            domain_id=domain.id,
            record_type="CNAME",
            name="app.example.com",
            value="unclaimed-app.herokuapp.com",
            ttl=300,
        )

        record2 = DNSRecord(
            domain_id=domain.id,
            record_type="A",
            name="www.example.com",
            value="203.0.113.10",
            ttl=300,
        )

        db.add_all([record1, record2])
        db.commit()

        return {
            "message": "Seed data created",
            "domain_id": domain.id
        }

    finally:
        db.close()

@router.get("/domains")
def get_domains():
    db = SessionLocal()

    try:
        domains = db.query(Domain).all()

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