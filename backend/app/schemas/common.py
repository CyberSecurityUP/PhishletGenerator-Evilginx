from pydantic import BaseModel
from typing import Optional
from enum import Enum


class AnalysisStatus(str, Enum):
    PENDING = "pending"
    SCRAPING = "scraping"
    ANALYZING = "analyzing"
    GENERATING = "generating"
    COMPLETE = "complete"
    ERROR = "error"


class ProgressUpdate(BaseModel):
    status: AnalysisStatus
    step: int
    total_steps: int
    message: str
    detail: Optional[str] = None
