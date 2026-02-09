# RTLPhishletGenerator

Automated Evilginx Phishlet Generator for Authorized Red Team Engagements.

## Overview

RTLPhishletGenerator analyzes target login pages and generates production-ready Evilginx v3 phishlet YAML configurations. It uses Playwright browser automation to map authentication flows, detect login forms, capture cookies, and discover all involved domains — then produces a valid phishlet with optional AI refinement.

**This tool is designed exclusively for authorized red team and purple team security testing engagements. All users must have proper NDA and written authorization.**

## Features

- **Automated URL Analysis** — Playwright-powered browser analysis detects login forms, authentication flows, cookies, and all involved domains
- **Intelligent Phishlet Generation** — Rule-based engine with known platform patterns (Microsoft 365, Google, Okta, GitHub, AWS)
- **AI Enhancement** — Optional LLM integration (DeepSeek, Claude, OpenAI) via litellm for improved accuracy
- **Built-in Validation** — Schema validation and cross-section logical checks for Evilginx v3 compatibility
- **YAML Editor** — Full-featured Monaco editor with syntax highlighting
- **Real-time Progress** — WebSocket-based analysis progress with step-by-step feedback
- **Web GUI** — Modern dark-themed interface with wizard workflow

## Prerequisites

- Python 3.11+
- Node.js 20+
- Docker (optional)

## Quick Start

### Option 1: Docker

```bash
cp .env.example .env
# Edit .env with your AI API key (optional)
docker-compose up -d
```

Open http://localhost:3000

### Option 2: Manual Setup

```bash
# Backend
cd backend
pip install -r requirements.txt
playwright install chromium
cd ..

# Frontend
cd frontend
npm install
cd ..

# Run both (requires Make)
make dev
```

- Backend: http://localhost:8000 (API docs at /docs)
- Frontend: http://localhost:5173

## Configuration

Copy `.env.example` to `.env` and configure:

```env
# AI Configuration (optional)
AI_API_KEY=your-api-key-here
AI_MODEL=deepseek/deepseek-chat

# Other supported models:
# AI_MODEL=claude-3-5-sonnet-20241022
# AI_MODEL=gpt-4o
# AI_MODEL=anthropic/claude-3-haiku
```

## AI Integration

RTLPhishletGenerator uses [litellm](https://github.com/BerriAI/litellm) for multi-provider AI support. The AI layer is **optional** — the rule-based engine always produces a baseline phishlet. AI refines it with:

- Platform-specific cookie/credential knowledge
- Missing subdomain detection
- Cross-domain sub_filter suggestions
- JavaScript injection recommendations for SPA targets

Supported providers: DeepSeek, Anthropic Claude, OpenAI, Azure OpenAI, Google Gemini, and any litellm-compatible model.

## Usage

1. **Enter Target URL** — Provide the login page URL (e.g., `https://login.example.com/signin`)
2. **Review Analysis** — Check discovered domains, login forms, cookies, and auth flow
3. **Generate Phishlet** — Click "Generate" to produce the YAML configuration
4. **Edit & Validate** — Fine-tune in the Monaco editor, run validation
5. **Export** — Download the `.yaml` file for use with Evilginx

## API Reference

| Endpoint | Method | Description |
|---|---|---|
| `/api/v1/health` | GET | Health check |
| `/api/v1/analyze/` | POST | Analyze a target URL |
| `/api/v1/analyze/ws` | WebSocket | Analyze with real-time progress |
| `/api/v1/generate/from-url` | POST | End-to-end: analyze + generate |
| `/api/v1/generate/from-analysis` | POST | Generate from existing analysis |
| `/api/v1/generate/ai-status` | GET | Check AI configuration status |
| `/api/v1/validate/` | POST | Validate phishlet YAML |

Full API documentation available at http://localhost:8000/docs when the backend is running.

## Project Structure

```
├── backend/
│   ├── app/
│   │   ├── main.py          # FastAPI application
│   │   ├── config.py        # Settings (pydantic-settings)
│   │   ├── routers/         # API endpoints
│   │   ├── services/        # Core business logic
│   │   │   ├── scraper.py   # Playwright website analysis
│   │   │   ├── analyzer.py  # Analysis orchestration
│   │   │   ├── generator.py # Phishlet YAML generation
│   │   │   ├── ai_service.py # LLM integration
│   │   │   └── validator.py # Phishlet validation
│   │   └── schemas/         # Pydantic models
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── components/      # React components
│   │   ├── pages/           # Page components
│   │   ├── services/        # API client
│   │   ├── store/           # Zustand state
│   │   └── hooks/           # Custom hooks
│   └── package.json
├── docs/
│   ├── lesson-01-using-rtlphishletgenerator.md
│   └── lesson-02-creating-phishlets-manual.md
├── docker-compose.yml
├── Makefile
└── .env.example
```

## Documentation

- [Lesson 1: Using RTLPhishletGenerator](docs/lesson-01-using-rtlphishletgenerator.md)
- [Lesson 2: Creating Phishlets - Techniques & Best Practices](docs/lesson-02-creating-phishlets-manual.md)

## Tech Stack

**Backend:** Python, FastAPI, Playwright, BeautifulSoup4, ruamel.yaml, litellm, Pydantic

**Frontend:** TypeScript, React, Vite, TailwindCSS, Monaco Editor, TanStack Query, Zustand

## Legal Disclaimer

This tool is provided for authorized security testing purposes only. Users must:

1. Have written authorization from the target organization
2. Operate under a valid NDA/SOW for the engagement
3. Comply with all applicable laws and regulations
4. Not use this tool for unauthorized access or malicious purposes

The developers assume no liability for misuse of this tool. By using RTLPhishletGenerator, you agree to use it exclusively within the scope of authorized security assessments.

## License

Private — Authorized use only under NDA.
