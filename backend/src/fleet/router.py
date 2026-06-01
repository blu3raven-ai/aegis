"""Fleet API router — exposes runner fleet status to the frontend."""
from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from src.fleet.service import FleetService

router = APIRouter(prefix="/api/v1/fleet", tags=["fleet"])


@router.get("/runners")
def list_fleet_runners() -> JSONResponse:
    """Return current status of all runner agents publishing heartbeats."""
    service = FleetService()
    runners = service.list_runners()
    return JSONResponse({
        "runners": [
            {
                "agent_id": r.agent_id,
                "hostname": r.hostname,
                "scanner_types": r.scanner_types,
                "in_flight_jobs": r.in_flight_jobs,
                "processed_total": r.processed_total,
                "last_heartbeat_at": r.last_heartbeat_at,
                "seconds_since_heartbeat": r.seconds_since_heartbeat,
                "status": r.status,
            }
            for r in runners
        ]
    })
