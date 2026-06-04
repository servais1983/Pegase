"""Public phishing-sim tracking endpoint.

This is the **only** unauthenticated POST endpoint in the API. It records a
click event keyed by a per-recipient opaque token. The endpoint:

  * never returns the recipient's identity,
  * stores only a SHA-256 of the source IP (defence against log-mining),
  * is rate-limited per IP by the shared SlowAPI limiter.
"""

from __future__ import annotations

import hashlib

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from pegase.core.audit import get_audit_log
from pegase.db.models import PhishClick
from pegase.db.session import get_session

router = APIRouter(prefix="/track", tags=["tracking"])


@router.api_route("/{token}", methods=["GET", "POST"])
async def track(
    token: str,
    request: Request,
    db: AsyncSession = Depends(get_session),
):
    if not token or len(token) < 16 or len(token) > 128:
        raise HTTPException(404, "unknown token")
    existing = await db.scalar(select(PhishClick).where(PhishClick.token == token))
    if existing is None:
        client_ip = request.client.host if request.client else ""
        ip_hash = hashlib.sha256(client_ip.encode("utf-8")).hexdigest() if client_ip else None
        click = PhishClick(
            campaign_id=request.query_params.get("c", "unknown"),
            token=token,
            user_agent=request.headers.get("user-agent", "")[:512],
            ip_hash=ip_hash,
        )
        db.add(click)
        get_audit_log().append(
            action="socialmatrix.click_recorded",
            actor="anonymous",
            mission="system",
            target=click.campaign_id,
            meta={"token": token},
        )
    return HTMLResponse(
        """<!doctype html><meta charset=utf-8>
<title>Security awareness</title>
<body style="font-family:sans-serif;max-width:560px;margin:80px auto">
  <h1>This was a phishing simulation</h1>
  <p>You interacted with a training page set up by your security team.
  No credentials have been transmitted or stored.</p>
  <p>If you have questions, contact your security team.</p>
</body>"""
    )
