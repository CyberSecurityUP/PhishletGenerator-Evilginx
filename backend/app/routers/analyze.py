import logging
import traceback

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, HTTPException

from app.schemas.analysis import AnalysisRequest, AnalysisResult
from app.schemas.common import ProgressUpdate, AnalysisStatus
from app.services.analyzer import SiteAnalyzer

router = APIRouter()
logger = logging.getLogger(__name__)


@router.post("/", response_model=AnalysisResult)
async def analyze_url(request: AnalysisRequest):
    try:
        analyzer = SiteAnalyzer()
        result = await analyzer.analyze(str(request.url))
        return result
    except Exception as e:
        logger.error(f"Analysis failed: {traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@router.websocket("/ws")
async def analyze_url_ws(websocket: WebSocket):
    await websocket.accept()
    try:
        data = await websocket.receive_json()
        url = data.get("url")
        if not url:
            await websocket.send_json({"error": "URL is required"})
            await websocket.close()
            return

        total_steps = 7
        current_step = [0]

        async def progress_callback(message: str):
            current_step[0] += 1
            update = ProgressUpdate(
                status=AnalysisStatus.ANALYZING,
                step=min(current_step[0], total_steps),
                total_steps=total_steps,
                message=message,
            )
            await websocket.send_json(update.model_dump())

        analyzer = SiteAnalyzer()
        result = await analyzer.analyze(url, callback=progress_callback)

        await websocket.send_json({
            "status": "complete",
            "result": result.model_dump(),
        })

    except WebSocketDisconnect:
        logger.info("Client disconnected during analysis")
    except Exception as e:
        logger.error(f"WebSocket analysis error: {e}")
        try:
            await websocket.send_json({"status": "error", "message": str(e)})
        except Exception:
            pass
    finally:
        try:
            await websocket.close()
        except Exception:
            pass
