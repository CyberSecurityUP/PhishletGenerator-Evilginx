import logging
from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.schemas.analysis import AnalysisResult
from app.schemas.phishlet import PhishletGenerateResponse
from app.services.analyzer import SiteAnalyzer
from app.services.generator import PhishletGenerator
from app.services.ai_service import AIService
from app.config import settings

router = APIRouter()
logger = logging.getLogger(__name__)


class GenerateFromURLRequest(BaseModel):
    url: str
    author: str = "@rtlphishletgen"
    use_ai: bool = False
    custom_name: Optional[str] = None


class GenerateFromAnalysisRequest(BaseModel):
    analysis: AnalysisResult
    author: str = "@rtlphishletgen"
    use_ai: bool = False
    custom_name: Optional[str] = None


@router.post("/from-url", response_model=PhishletGenerateResponse)
async def generate_from_url(request: GenerateFromURLRequest):
    try:
        analyzer = SiteAnalyzer()
        analysis = await analyzer.analyze(request.url)

        ai_service = AIService() if settings.ai_enabled else None
        generator = PhishletGenerator(ai_service=ai_service)
        result = await generator.generate(
            analysis=analysis,
            author=request.author,
            use_ai=request.use_ai,
            custom_name=request.custom_name,
        )
        return result
    except Exception as e:
        logger.error(f"Generation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/from-analysis", response_model=PhishletGenerateResponse)
async def generate_from_analysis(request: GenerateFromAnalysisRequest):
    try:
        ai_service = AIService() if settings.ai_enabled else None
        generator = PhishletGenerator(ai_service=ai_service)
        result = await generator.generate(
            analysis=request.analysis,
            author=request.author,
            use_ai=request.use_ai,
            custom_name=request.custom_name,
        )
        return result
    except Exception as e:
        logger.error(f"Generation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/ai-status")
async def check_ai_status():
    if not settings.ai_enabled:
        return {"enabled": False, "model": None, "connected": False}

    ai = AIService()
    connected = await ai.check_connection()
    return {
        "enabled": True,
        "model": settings.ai_model,
        "connected": connected,
    }
