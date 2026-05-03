from pydantic import BaseModel


class DomainCreate(BaseModel):
    # store the domain name the user wants dnscope to monitor
    domain_name: str


class DNSZoneUpload(BaseModel):
    # store raw dns zone export text pasted or uploaded by the user
    zone_text: str
