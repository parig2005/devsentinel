"""Pydantic request/response models for the DevSentinel AI engine.

Field aliases are camelCase so these line up with the Java DTOs without any
manual mapping on either side. `populate_by_name=True` means the models also
accept snake_case, which keeps curl testing convenient.
"""

from typing import Optional

from pydantic import BaseModel, ConfigDict, Field


def _to_camel(snake: str) -> str:
    first, *rest = snake.split("_")
    return first + "".join(word.capitalize() for word in rest)


class CamelModel(BaseModel):
    model_config = ConfigDict(alias_generator=_to_camel, populate_by_name=True)


class PredictRequest(CamelModel):
    """Payload sent by the Spring Boot AiAnalysisClient."""

    class_name: Optional[str] = Field(default=None, description="Enclosing class name")
    method_name: Optional[str] = Field(default=None, description="Method being analyzed")
    code_snippet: str = Field(..., min_length=1, description="Raw Java source of the snippet")
    start_line: int = Field(default=0, ge=0, description="1-based start line in the original file")
    static_analysis_hint: Optional[str] = Field(
        default=None,
        description="Comma-separated hints from the Java static pass, e.g. 'possible_sql_injection'",
    )


class PredictResponse(CamelModel):
    """Structured finding returned to the Spring Boot backend."""

    vulnerability_type: str = Field(..., description="e.g. SQL_INJECTION, or NONE if clean")
    severity_score: float = Field(..., ge=0.0, le=10.0, description="0.0 - 10.0")
    issue_description: str
    suggested_fix: Optional[str] = None
    owasp_category: Optional[str] = None
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    model_version: str = Field(default="unknown")


class HealthResponse(CamelModel):
    status: str
    model_loaded: bool
    model_name: str
    device: str
