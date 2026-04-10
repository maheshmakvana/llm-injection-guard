"""
Drop-in middleware for FastAPI and Flask.
"""
import logging
from typing import Optional, Callable, List
from .scanner import PromptScanner
from .exceptions import InjectionDetectedError

logger = logging.getLogger(__name__)

def create_fastapi_middleware(
    scanner: Optional[PromptScanner] = None,
    scan_fields: Optional[List[str]] = None,
    on_injection: Optional[Callable] = None,
):
    """
    FastAPI middleware factory for prompt injection defense.

    Usage:
        from fastapi import FastAPI
        from promptshield.middleware import create_fastapi_middleware

        app = FastAPI()
        app.middleware("http")(create_fastapi_middleware())
    """
    try:
        from fastapi import Request, Response
        from fastapi.responses import JSONResponse
        import json
    except ImportError:
        raise ImportError("FastAPI is required: pip install fastapi")

    _scanner = scanner or PromptScanner()
    _scan_fields = scan_fields or ["prompt", "message", "query", "input", "text", "content"]

    async def middleware(request: Request, call_next: Callable):
        if request.method in ("POST", "PUT", "PATCH"):
            try:
                body = await request.body()
                if body:
                    data = json.loads(body)
                    for field in _scan_fields:
                        if field in data and isinstance(data[field], str):
                            try:
                                _scanner.scan(data[field], metadata={"field": field, "path": request.url.path})
                            except InjectionDetectedError as e:
                                logger.warning(f"Blocked injection attempt on field '{field}': {e}")
                                if on_injection:
                                    return on_injection(request, e)
                                return JSONResponse(
                                    status_code=400,
                                    content={
                                        "error": "prompt_injection_detected",
                                        "message": "Input rejected due to security policy.",
                                        "threat_level": e.threat_level,
                                    }
                                )
            except (json.JSONDecodeError, Exception) as e:
                logger.debug(f"Middleware could not parse body: {e}")
        return await call_next(request)

    return middleware


def create_flask_middleware(
    app,
    scanner: Optional[PromptScanner] = None,
    scan_fields: Optional[List[str]] = None,
):
    """
    Flask before_request hook for prompt injection defense.

    Usage:
        from flask import Flask
        from promptshield.middleware import create_flask_middleware

        app = Flask(__name__)
        create_flask_middleware(app)
    """
    try:
        from flask import request, jsonify, abort
    except ImportError:
        raise ImportError("Flask is required: pip install flask")

    _scanner = scanner or PromptScanner()
    _scan_fields = scan_fields or ["prompt", "message", "query", "input", "text", "content"]

    @app.before_request
    def check_injection():
        if request.method in ("POST", "PUT", "PATCH") and request.is_json:
            data = request.get_json(silent=True) or {}
            for field in _scan_fields:
                if field in data and isinstance(data[field], str):
                    try:
                        _scanner.scan(data[field], metadata={"field": field, "path": request.path})
                    except InjectionDetectedError as e:
                        logger.warning(f"Flask: blocked injection on field '{field}'")
                        return jsonify({
                            "error": "prompt_injection_detected",
                            "message": "Input rejected due to security policy.",
                            "threat_level": e.threat_level,
                        }), 400
