import os
from pathlib import Path
from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

app = FastAPI(title="LINK X Sistemas - API de Asistencia", version="1.0.0")
BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

@app.get("/api/health")
def health():
    return {"status": "ok", "service": "LINK X Asistencia"}

@app.get("/")
def home():
    index_file = STATIC_DIR / "index.html"
    if not index_file.exists():
        return {"message": "Frontend pendiente de instalar", "docs": "/docs"}
    return FileResponse(str(index_file))
