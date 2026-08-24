"""CoreIDS Backend — FastAPI application entry point.

Usage:
    uvicorn app.main:app --reload --port 8000

Environment:
    DATABASE_URL  — PostgreSQL connection string
    JWT_SECRET    — secret for signing tokens (change in production!)
"""

import asyncio
import io
import os
import tarfile
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, PlainTextResponse, StreamingResponse
from sqlalchemy import text

from .database import Base, engine, SessionLocal
from .routers import auth, devices, alerts, dashboard, logs, rules, reports, stream
from .central_runtime import UserRuntimeManager


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Create tables on startup (for dev — use Alembic in production)
    loop = asyncio.get_event_loop()
    try:
        await loop.run_in_executor(None, lambda: Base.metadata.create_all(bind=engine))
    except Exception:
        import logging
        logging.getLogger("coreids").warning("Database unreachable — tables not created, app running in degraded mode")
    # Start central runtime manager for event processing
    manager = UserRuntimeManager()
    manager.start()
    app.state.runtime_manager = manager
    # Share runtime manager's event loop with alert broadcast module
    alerts._event_loop = manager._loop
    yield
    manager.stop()


app = FastAPI(
    title="CoreIDS API",
    version="0.1.0",
    description="Backend for the CoreIDS SaaS platform",
    lifespan=lifespan,
)

# CORS — configurable origins via env var; default allows same-origin only
_cors_origins_str = os.getenv("CORS_ORIGINS", "")
_cors_origins = [o.strip() for o in _cors_origins_str.split(",") if o.strip()] if _cors_origins_str else []
_cors_credentials = _cors_origins_str != ""  # only allow credentials when origins are explicitly set
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=_cors_credentials,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "connect-src 'self' ws: wss:; "
        "img-src 'self' data:; "
        "form-action 'self'; "
        "base-uri 'self'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response

# Mount routers (must come before static mount)
app.include_router(auth.router)
app.include_router(devices.router)
app.include_router(alerts.router)        # user-facing /api/alerts/*
app.include_router(alerts.ingest_router)  # daemon-facing /api/v1/*
app.include_router(dashboard.router)
app.include_router(logs.router)
app.include_router(rules.router)
app.include_router(reports.router)
app.include_router(stream.router)


@app.get("/health")
def health():
    db_ok = False
    db = SessionLocal()
    try:
        db.execute(text("SELECT 1"))
        db_ok = True
    except Exception:
        pass
    finally:
        db.close()
    return {"status": "ok" if db_ok else "degraded", "database": "ok" if db_ok else "error"}


# Serve the single-page frontend at root
static_dir = Path(__file__).resolve().parent.parent / "static"
index_path = static_dir / "index.html"


@app.get("/", response_class=HTMLResponse)
def index():
    if index_path.exists():
        return HTMLResponse(index_path.read_text())
    return HTMLResponse("<h1>CoreIDS Backend</h1><p>Frontend not built. Run the API client at <code>/docs</code></p>")


install_script_path = static_dir / "install.sh"


@app.get("/install.sh", response_class=PlainTextResponse)
def install_script():
    if install_script_path.exists():
        return PlainTextResponse(install_script_path.read_text(), media_type="text/x-shellscript")
    return PlainTextResponse("echo 'Install script not found'", status_code=404)


PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


@app.get("/download/source.tar.gz", response_class=StreamingResponse)
def download_source_tarball():
    include_dir = PROJECT_ROOT / "include"
    if not include_dir.exists():
        return PlainTextResponse("Source not available", status_code=404)
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for path in include_dir.rglob("*"):
            tar.add(path, arcname=path.relative_to(PROJECT_ROOT))
        tools_dir = PROJECT_ROOT / "tools"
        for f in ("ids_production.cpp", "ids_production.conf"):
            p = tools_dir / f
            if p.exists():
                tar.add(p, arcname=p.relative_to(PROJECT_ROOT))
        cmake = PROJECT_ROOT / "CMakeLists.txt"
        if cmake.exists():
            tar.add(cmake, arcname=cmake.relative_to(PROJECT_ROOT))
        docker = PROJECT_ROOT / "Dockerfile"
        if docker.exists():
            tar.add(docker, arcname=docker.relative_to(PROJECT_ROOT))
    buf.seek(0)
    return StreamingResponse(buf, media_type="application/gzip",
                            headers={"Content-Disposition": "attachment; filename=coreids-source.tar.gz"})


@app.get("/download/coreids-sensor-{arch}", response_class=StreamingResponse)
def download_prebuilt(arch: str):
    VALID_ARCHS = {"amd64", "x86_64", "arm64", "aarch64", "armv7"}
    if arch not in VALID_ARCHS:
        return PlainTextResponse("Unsupported architecture", status_code=400)
    binary_path = PROJECT_ROOT / f"build/coreids-sensor-linux-{arch}"
    if binary_path.exists():
        return StreamingResponse(open(binary_path, "rb"), media_type="application/octet-stream",
                                 headers={"Content-Disposition": f"attachment; filename=coreids-sensor-linux-{arch}"})
    # Try build/ids_production (cmake output) or build/ids_production_static
    for candidate in (PROJECT_ROOT / "build").glob("ids_production*"):
        f = open(candidate, "rb")
        return StreamingResponse(f, media_type="application/octet-stream",
                                 headers={"Content-Disposition": f"attachment; filename=coreids-sensor-linux-{arch}"})
    return PlainTextResponse("Binary not found for this architecture. Build from source via /download/source.tar.gz",
                             status_code=404)



