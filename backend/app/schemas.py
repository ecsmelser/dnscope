from pydantic import BaseModel


class DomainCreate(BaseModel):
    # store the domain name the user wants dnscope to monitor
    domain_name: str
