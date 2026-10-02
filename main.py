"""CYBERGUARD Main Application Entrypoint."""
import uvicorn
from app.backend.main import app
from app.backend.core.config import settings

if __name__ == "__main__":
    uvicorn.run(
        "app.backend.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG,
    )