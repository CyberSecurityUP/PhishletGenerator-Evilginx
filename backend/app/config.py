from pathlib import Path
from pydantic_settings import BaseSettings
from typing import Optional

# Resolve .env from project root (parent of backend/)
_env_file = Path(__file__).resolve().parent.parent.parent / ".env"


class Settings(BaseSettings):
    # AI Configuration
    ai_api_key: Optional[str] = None
    ai_model: str = "deepseek/deepseek-chat"
    ai_enabled: bool = False

    # Server
    cors_origins: list[str] = ["http://localhost:5173", "http://localhost:3000"]
    debug: bool = False

    # Playwright
    playwright_headless: bool = True
    playwright_timeout: int = 30000

    # Evilginx
    evilginx_min_ver: str = "3.2.0"

    model_config = {
        "env_file": str(_env_file),
        "env_file_encoding": "utf-8",
    }


settings = Settings()

if settings.ai_api_key:
    settings.ai_enabled = True
