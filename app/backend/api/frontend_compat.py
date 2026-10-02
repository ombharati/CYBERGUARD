"""Frontend Compatibility Router.

Supports unversioned /api/scans endpoints expected by the existing app/frontend/script.js.
Ensures zero frontend modifications are needed for seamless hackathon operation.
"""
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.backend.core.database import get_db
from app.backend.schemas.scan import ScanCreateRequest, ScanResponse
from app.backend.services.scan_service import ScanService

router = APIRouter(prefix="/scans", tags=["Frontend Compatibility"])
_scan_service = ScanService()


@router.post(
    "",
    response_model=ScanResponse,
    status_code=status.HTTP_200_OK,
    summary="Direct scan endpoint for existing frontend",
)
async def create_scan_compat(
    request: ScanCreateRequest,
    db: Session = Depends(get_db),
):
    """
    Executes scan synchronously so frontend script.js receives the completed
    report directly and renders showResult() without client-side polling changes.
    """
    try:
        scan = await _scan_service.create_scan(
            db=db,
            input_type=request.input_type,
            data=request.data,
            run_sync=True,
        )
        return scan.to_dict()
    except ValueError as val_err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(val_err))
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Analysis failed: {str(exc)}",
        )


@router.get(
    "",
    response_model=List[ScanResponse],
    summary="History endpoint for existing frontend",
)
def list_scans_compat(
    db: Session = Depends(get_db),
):
    scans = _scan_service.list_recent_scans(db=db, limit=50)
    return [s.to_dict() for s in scans]
