"""Attribution Router — domain intelligence (WHOIS + DNS)"""

from fastapi import APIRouter
from ..models import DomainAttributionRequest, DomainAttributionResponse
from ..services.domain_lookup import lookup_domain

router = APIRouter(prefix="/attribution", tags=["Attribution"])


@router.post("/domain", response_model=DomainAttributionResponse)
async def attribute_domain(request: DomainAttributionRequest):
    """Look up DNS records and WHOIS data for a domain."""
    result = await lookup_domain(request.domain)
    return DomainAttributionResponse(**result)
