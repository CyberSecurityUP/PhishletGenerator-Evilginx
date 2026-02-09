import json
import logging
from pathlib import Path
from datetime import datetime

from fastapi import APIRouter, HTTPException

from app.schemas.saved import (
    SavedPhishlet,
    SavedPhishletCreate,
    SavedPhishletUpdate,
    SavedPhishletList,
)
from app.services.validator import PhishletValidator

router = APIRouter()
logger = logging.getLogger(__name__)

DATA_DIR = Path(__file__).parent.parent.parent / "data" / "phishlets"


def _ensure_data_dir():
    DATA_DIR.mkdir(parents=True, exist_ok=True)


def _get_phishlet_path(phishlet_id: str) -> Path:
    safe_id = phishlet_id.replace("/", "").replace("\\", "").replace("..", "")
    return DATA_DIR / f"{safe_id}.json"


def _load_phishlet(phishlet_id: str) -> SavedPhishlet:
    path = _get_phishlet_path(phishlet_id)
    if not path.exists():
        raise HTTPException(status_code=404, detail=f"Phishlet '{phishlet_id}' not found")
    try:
        data = json.loads(path.read_text())
        return SavedPhishlet(**data)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to load phishlet: {e}")


def _save_phishlet(phishlet: SavedPhishlet):
    _ensure_data_dir()
    path = _get_phishlet_path(phishlet.id)
    path.write_text(phishlet.model_dump_json(indent=2))


@router.get("/", response_model=SavedPhishletList)
async def list_phishlets():
    _ensure_data_dir()
    phishlets = []
    for file in sorted(DATA_DIR.glob("*.json"), key=lambda f: f.stat().st_mtime, reverse=True):
        try:
            data = json.loads(file.read_text())
            phishlets.append(SavedPhishlet(**data))
        except Exception as e:
            logger.warning(f"Skipping corrupt phishlet file {file.name}: {e}")
    return SavedPhishletList(phishlets=phishlets, total=len(phishlets))


@router.post("/", response_model=SavedPhishlet, status_code=201)
async def save_phishlet(request: SavedPhishletCreate):
    validator = PhishletValidator()
    validation = validator.validate_yaml(request.yaml_content)

    phishlet = SavedPhishlet(
        name=request.name,
        author=request.author,
        target_url=request.target_url,
        description=request.description,
        tags=request.tags,
        yaml_content=request.yaml_content,
        validation_status="valid" if validation.valid else "invalid",
    )
    _save_phishlet(phishlet)
    return phishlet


@router.get("/{phishlet_id}", response_model=SavedPhishlet)
async def get_phishlet(phishlet_id: str):
    return _load_phishlet(phishlet_id)


@router.put("/{phishlet_id}", response_model=SavedPhishlet)
async def update_phishlet(phishlet_id: str, request: SavedPhishletUpdate):
    phishlet = _load_phishlet(phishlet_id)

    if request.name is not None:
        phishlet.name = request.name
    if request.author is not None:
        phishlet.author = request.author
    if request.target_url is not None:
        phishlet.target_url = request.target_url
    if request.description is not None:
        phishlet.description = request.description
    if request.tags is not None:
        phishlet.tags = request.tags
    if request.yaml_content is not None:
        phishlet.yaml_content = request.yaml_content
        validator = PhishletValidator()
        validation = validator.validate_yaml(request.yaml_content)
        phishlet.validation_status = "valid" if validation.valid else "invalid"

    phishlet.updated_at = datetime.utcnow()
    _save_phishlet(phishlet)
    return phishlet


@router.delete("/{phishlet_id}")
async def delete_phishlet(phishlet_id: str):
    path = _get_phishlet_path(phishlet_id)
    if not path.exists():
        raise HTTPException(status_code=404, detail="Phishlet not found")
    path.unlink()
    return {"detail": "Phishlet deleted"}
