"""CYBERGUARD Configuration Management."""
import os
from pathlib import Path
from typing import List, Optional
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Server settings
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    DEBUG: bool = False
    ALLOWED_ORIGINS: str = "*"

    # Database
    DATABASE_URL: str = "postgresql+psycopg://cyberguard:cyberguard@localhost:5432/cyberguard"

    # Redis & Queue
    REDIS_URL: str = "redis://localhost:6379/0"
    SCAN_QUEUE_NAME: str = "cyberguard:scans"
    SCAN_TIMEOUT_SECONDS: int = 120
    MAX_SCAN_RETRIES: int = 2

    # Local AI - Ollama (Qwen)
    OLLAMA_BASE_URL: str = "http://localhost:11434"
    OLLAMA_MODEL: str = "qwen3:8b"
    OLLAMA_TIMEOUT_SECONDS: float = 60.0

    # Local AI - Laya (URL System 1 Decision Model)
    LAYA_VENV_PATH: Optional[str] = None
    LAYA_DEVICE: str = "cpu"
    LAYA_TIMEOUT_SECONDS: float = 15.0

    # Optional External Threat Intelligence
    ENABLE_EXTERNAL_INTEL: bool = False
    VIRUSTOTAL_API_KEY: Optional[str] = None
    URLSCAN_API_KEY: Optional[str] = None
    EXTERNAL_INTEL_TIMEOUT_SECONDS: float = 5.0

    # Security & Input Limits
    MAX_URL_LENGTH: int = 2048
    MAX_EMAIL_BODY_LENGTH: int = 20000
    MAX_CONTENT_LENGTH: int = 20000
    API_KEY: str = ""

    @property
    def auth_enabled(self) -> bool:
        return bool(self.API_KEY)

    @property
    def cors_origins(self) -> List[str]:
        if self.ALLOWED_ORIGINS == "*":
            return ["*"]
        return [origin.strip() for origin in self.ALLOWED_ORIGINS.split(",") if origin.strip()]

    def resolve_laya_path(self) -> Optional[Path]:
        """Locate Laya venv or package directory without hardcoding user home paths."""
        if self.LAYA_VENV_PATH:
            p = Path(self.LAYA_VENV_PATH).expanduser()
            if p.exists():
                return p

        # Check environment variable
        env_path = os.environ.get("LAYA_VENV_PATH")
        if env_path:
            p = Path(env_path).expanduser()
            if p.exists():
                return p

        # Auto-discover under user home directory
        home = Path.home()
        candidates = [
            home / "laya-test" / ".venv",
            home / ".venv-laya",
            home / "laya" / ".venv",
        ]
        for candidate in candidates:
            if candidate.exists():
                return candidate

        return None


settings = Settings()
