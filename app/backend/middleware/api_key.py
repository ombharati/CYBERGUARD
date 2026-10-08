import hmac
import logging

from fastapi import Request, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.backend.core.config import settings

logger = logging.getLogger("cyberguard.auth")

class APIKeyMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        
        exempt_paths = {"/health", "/docs", "/redoc", "/openapi.json"}
        if path in exempt_paths:
            return await call_next(request)
            
        # Enforce API key only on API routes.
        # Static files (/) are exempted by not starting with /api/.
        if path.startswith("/api/"):
            if settings.auth_enabled:
                api_key_header = request.headers.get("X-API-Key")
                if not api_key_header:
                    logger.warning(f"Unauthorized access attempt to {path}: Missing API key")
                    return JSONResponse(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        content={"detail": "Missing API key"}
                    )
                    
                if not hmac.compare_digest(api_key_header, settings.API_KEY):
                    masked_key = f"***{api_key_header[-4:]}" if len(api_key_header) >= 4 else "***"
                    logger.warning(f"Unauthorized access attempt to {path}: Invalid API key provided ({masked_key})")
                    return JSONResponse(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        content={"detail": "Invalid API key"}
                    )
                    
        return await call_next(request)
