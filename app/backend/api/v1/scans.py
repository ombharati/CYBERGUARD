"""API v1 Scans Router.

Routes handle HTTP concerns only.
"""
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Header, status, Response
from sqlalchemy.orm import Session
from app.backend.core.database import get_db
from app.backend.schemas.scan import ScanCreateRequest, ScanResponse
from app.backend.services.scan_service import ScanService

router = APIRouter(prefix="/scans", tags=["Scans v1"])
_scan_service = ScanService()


@router.post(
    "",
    response_model=ScanResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create and queue a cybersecurity scan",
)
async def create_scan(
    request: ScanCreateRequest,
    sync: bool = Query(False, description="Wait for scan completion before responding"),
    idempotency_key: Optional[str] = Header(None, alias="Idempotency-Key"),
    db: Session = Depends(get_db),
):
    try:
        scan = await _scan_service.create_scan(
            db=db,
            input_type=request.input_type,
            data=request.data,
            run_sync=sync,
            idempotency_key=idempotency_key,
        )
        return scan.to_dict()
    except ValueError as val_err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(val_err))
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to initiate scan: {str(exc)}",
        )


@router.get(
    "/{scan_id}",
    response_model=ScanResponse,
    summary="Get scan status and detailed report",
)
def get_scan(
    scan_id: str,
    db: Session = Depends(get_db),
):
    scan = _scan_service.get_scan(db=db, scan_id=scan_id)
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan with ID '{scan_id}' not found.",
        )
    return scan.to_dict()


@router.get(
    "/{scan_id}/report",
    summary="Download one-page narrative security report as plain text",
)
def get_scan_report(
    scan_id: str,
    db: Session = Depends(get_db),
):
    scan = _scan_service.get_scan(db=db, scan_id=scan_id)
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan with ID '{scan_id}' not found.",
        )

    report_content = scan.report_text
    if not report_content:
        if scan.status == "completed":
            from app.backend.services.ai.qwen_adapter import build_deterministic_report
            report_content = build_deterministic_report(
                input_type=scan.input_type,
                target=scan.target,
                risk_score=scan.risk_score or 0,
                classification=scan.classification or "Safe",
                findings=scan.findings,
                providers_used=["Deterministic Heuristics Engine"],
                providers_not_used=[],
            )
        else:
            report_content = f"CYBERGUARD Security Analysis for Scan ID: {scan_id}\nStatus: {scan.status.capitalize()}\nReport is not yet ready."

    filename = f"cyberguard-report-{scan_id}.txt"
    return Response(
        content=report_content,
        media_type="text/plain; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"'
        },
    )


@router.get(
    "",
    response_model=List[ScanResponse],
    summary="List recent scans",
)
def list_scans(
    limit: int = Query(50, ge=1, le=100),
    db: Session = Depends(get_db),
):
    scans = _scan_service.list_recent_scans(db=db, limit=limit)
    return [s.to_dict() for s in scans]
