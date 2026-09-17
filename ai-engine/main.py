"""DevSentinel AI Service — FastAPI semantic scoring for Java code snippets.

Start with:
    uvicorn main:app --host 127.0.0.1 --port 8000

Endpoints
---------
GET  /health           readiness + whether transformer weights are loaded
POST /api/v1/predict   score one Java method snippet

Honest description of what this service does
--------------------------------------------
`microsoft/codebert-base` is a BASE encoder. It has no classification head
trained on vulnerability labels, so it cannot, by itself, decide whether code
is vulnerable. This service therefore does two separate things:

  1. An explainable signature engine detects known weakness patterns. This is
     what produces the vulnerability type, severity, and remediation.
  2. CodeBERT produces embeddings, used to measure semantic similarity between
     the snippet and a natural-language description of the matched weakness.
     That similarity becomes the CONFIDENCE score.

Nothing here is a fine-tuned OWASP classifier, and the code never claims to be.
See `CodeAnalyzer` in app/analyzer.py for the seam where a fine-tuned
`AutoModelForSequenceClassification` would be plugged in.
"""

from __future__ import annotations

import logging
import os
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.analyzer import CodeAnalyzer
from app.schemas import HealthResponse, PredictRequest, PredictResponse

# ---------------------------------------------------------------------------
# Configuration — environment driven, no secrets in source
# ---------------------------------------------------------------------------

MODEL_NAME = os.getenv("DEVSENTINEL_MODEL", "microsoft/codebert-base")
DEVICE = os.getenv("DEVSENTINEL_DEVICE", "cpu")
MAX_SNIPPET_CHARS = int(os.getenv("DEVSENTINEL_MAX_SNIPPET_CHARS", "20000"))

# Set DEVSENTINEL_SKIP_MODEL=1 to start instantly in rule-only mode.
# Useful on a laptop with no spare disk/bandwidth for the ~500 MB download.
SKIP_MODEL = os.getenv("DEVSENTINEL_SKIP_MODEL", "0").lower() in ("1", "true", "yes")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("devsentinel")

# One shared analyzer. Loading a transformer costs seconds and hundreds of MB,
# so it happens once at startup — never per request.
analyzer = CodeAnalyzer(model_name=MODEL_NAME, device=DEVICE)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    """Load the model on startup; release it on shutdown."""
    logger.info("Starting DevSentinel AI service...")
    if SKIP_MODEL:
        logger.warning(
            "DEVSENTINEL_SKIP_MODEL is set — starting in rule-only mode "
            "(no transformer weights, confidence defaults to 0.5)."
        )
    else:
        # .load() degrades gracefully on its own if transformers/torch are
        # missing or the download fails, so no try/except is needed here.
        analyzer.load()
    yield
    logger.info("Shutting down DevSentinel AI service...")
    analyzer.model = None
    analyzer.tokenizer = None


app = FastAPI(
    title="DevSentinel AI Service",
    description=(
        "Semantic confidence scoring for Java code snippets. "
        "Signature engine + CodeBERT embeddings. Not a fine-tuned classifier."
    ),
    version="1.0.0",
    lifespan=lifespan,
)


@app.middleware("http")
async def add_timing_header(request: Request, call_next):
    """Expose per-request inference time — handy evidence for the report."""
    started = time.perf_counter()
    response = await call_next(request)
    response.headers["X-Inference-Time-Ms"] = f"{(time.perf_counter() - started) * 1000:.1f}"
    return response


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@app.get("/health", response_model=HealthResponse, tags=["ops"])
async def health() -> HealthResponse:
    """Readiness probe. Spring Boot calls this to decide ONLINE vs DEGRADED."""
    return HealthResponse(
        status="UP",
        model_loaded=analyzer.is_loaded,
        model_name=MODEL_NAME if analyzer.is_loaded else "rule-only",
        device=DEVICE,
    )


@app.post(
    "/api/v1/predict",
    response_model=PredictResponse,
    status_code=status.HTTP_200_OK,
    tags=["inference"],
)
async def predict(payload: PredictRequest) -> PredictResponse:
    """Analyse one Java method snippet.

    Pydantic validates the body first, so malformed input returns 422 and never
    reaches the model.
    """
    snippet = payload.code_snippet

    # Bound the work: a pathological input should not stall the event loop.
    if len(snippet) > MAX_SNIPPET_CHARS:
        logger.warning(
            "Truncating snippet for %s#%s from %d to %d chars",
            payload.class_name, payload.method_name, len(snippet), MAX_SNIPPET_CHARS,
        )
        snippet = snippet[:MAX_SNIPPET_CHARS]

    result = analyzer.analyze(snippet, hint=payload.static_analysis_hint)

    logger.info(
        "%s#%s -> %s (confidence %.2f)",
        payload.class_name or "?", payload.method_name or "?",
        result["vulnerability_type"], result["confidence"],
    )

    return PredictResponse(**result)


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------


@app.exception_handler(RequestValidationError)
async def validation_error_handler(_request: Request, exc: RequestValidationError):
    """422 with a compact message instead of FastAPI's verbose default."""
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"detail": "Invalid request body", "errors": exc.errors()[:3]},
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, _exc: Exception):
    """Structured 500 rather than an HTML stack trace.

    The Java client treats any failure here as a fallback and switches the run
    to DEGRADED, so this response shape matters for the other side of the wire.
    """
    logger.exception("Unhandled error on %s", request.url.path)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Internal inference error", "path": str(request.url.path)},
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
