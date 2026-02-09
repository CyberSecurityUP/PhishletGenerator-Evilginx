import uuid
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field


class SavedPhishletBase(BaseModel):
    name: str
    author: str = "@rtlphishletgen"
    target_url: str = ""
    description: str = ""
    tags: list[str] = []


class SavedPhishletCreate(SavedPhishletBase):
    yaml_content: str


class SavedPhishletUpdate(BaseModel):
    name: Optional[str] = None
    author: Optional[str] = None
    target_url: Optional[str] = None
    description: Optional[str] = None
    tags: Optional[list[str]] = None
    yaml_content: Optional[str] = None


class SavedPhishlet(SavedPhishletBase):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    yaml_content: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    validation_status: str = "unknown"


class SavedPhishletList(BaseModel):
    phishlets: list[SavedPhishlet]
    total: int
