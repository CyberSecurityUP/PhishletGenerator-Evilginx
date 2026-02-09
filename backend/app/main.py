from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.routers import analyze, generate, validate, phishlets

app = FastAPI(
    title="RTLPhishletGenerator API",
    version="1.0.0",
    description="Automated Evilginx Phishlet Generator for Red Team Engagements",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(analyze.router, prefix="/api/v1/analyze", tags=["Analysis"])
app.include_router(generate.router, prefix="/api/v1/generate", tags=["Generation"])
app.include_router(validate.router, prefix="/api/v1/validate", tags=["Validation"])
app.include_router(phishlets.router, prefix="/api/v1/phishlets", tags=["Library"])


@app.get("/api/v1/health")
async def health():
    return {"status": "ok", "ai_enabled": settings.ai_enabled}
