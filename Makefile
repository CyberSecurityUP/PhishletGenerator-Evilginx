.PHONY: install dev backend frontend build docker-up docker-down test lint

install:
	cd backend && pip install -r requirements.txt && playwright install chromium
	cd frontend && npm install

dev:
	$(MAKE) -j2 backend frontend

backend:
	cd backend && uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

frontend:
	cd frontend && npm run dev

build:
	cd frontend && npm run build

docker-up:
	docker-compose up -d --build

docker-down:
	docker-compose down

test:
	cd backend && pytest tests/ -v

lint:
	cd backend && ruff check app/
	cd frontend && npx tsc --noEmit
