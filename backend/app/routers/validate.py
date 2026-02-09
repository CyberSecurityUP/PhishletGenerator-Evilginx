from fastapi import APIRouter
from pydantic import BaseModel

from app.services.validator import PhishletValidator

router = APIRouter()


class ValidateRequest(BaseModel):
    yaml_content: str


class ValidateResponse(BaseModel):
    valid: bool
    errors: list[str]
    warnings: list[str]


@router.post("/", response_model=ValidateResponse)
async def validate_phishlet(request: ValidateRequest):
    validator = PhishletValidator()
    result = validator.validate_yaml(request.yaml_content)
    return ValidateResponse(
        valid=result.valid,
        errors=result.errors,
        warnings=result.warnings,
    )
