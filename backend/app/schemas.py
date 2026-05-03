from pydantic import BaseModel


class DomainCreate(BaseModel):
    # store the domain name the user wants dnscope to monitor
    domain_name: str


class DNSZoneUpload(BaseModel):
    # store raw dns zone export text pasted or uploaded by the user
    zone_text: str


class DomainScheduleUpdate(BaseModel):
    # turn scheduled scans on or off for one monitored domain
    scheduled_scans_enabled: bool

    # store how many minutes dnscope should wait between scheduled scans
    scan_interval_minutes: int = 60
