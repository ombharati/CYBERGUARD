"""Pydantic Request and Response Schemas."""
from datetime import datetime
from typing import List, Dict, Any, Optional, Union
from pydantic import BaseModel, Field, field_validator


class ScanCreateRequest(BaseModel):
    input_type: str = Field(..., description="'url', 'email', 'content', or 'logs'")
    data: Union[str, Dict[str, Any]] = Field(..., description="Target string or email dictionary")

    @field_validator("input_type")
    @classmethod
    def validate_input_type(cls, v: str) -> str:
        clean = v.strip().lower()
        if clean not in ("url", "email", "content", "logs", "identity", "headers"):
            raise ValueError("input_type must be one of: 'url', 'email', 'content', 'logs', 'identity', 'headers'")
        return clean

    @field_validator("data")
    @classmethod
    def validate_data(cls, v: Union[str, Dict[str, Any]]) -> Union[str, Dict[str, Any]]:
        if isinstance(v, str):
            clean = v.strip()
            if not clean:
                raise ValueError("Data cannot be empty")
            if len(clean) > 1048576:
                raise ValueError("Input data exceeds maximum allowed length of 1MB (1,048,576 characters)")
            return clean
        elif isinstance(v, dict):
            if not v:
                raise ValueError("Email data object cannot be empty")
            return v
        raise ValueError("Data must be a string or dictionary")


class FindingResponse(BaseModel):
    severity: str
    title: str
    description: str
    category: Optional[str] = None
    signal_type: Optional[str] = None
    weight: Optional[int] = 0
    evidence: Optional[str] = None
    source: Optional[str] = "deterministic"
    recommended_actions: Optional[List[str]] = Field(default_factory=list)


class SignalResponse(BaseModel):
    name: str
    value: int


class ScanResponse(BaseModel):
    id: str
    type: str
    target: str
    status: str
    score: int = 0
    classification: str = Field("Processing", description="Risk tier: 'Safe' (0-20), 'Low' (21-40), 'Medium' (41-60), 'High' (61-80), 'Critical' (81-100), or 'Processing'")
    summary: str = ""
    findings: List[FindingResponse] = Field(default_factory=list)
    signals: List[SignalResponse] = Field(default_factory=list)
    explanation: str = ""
    report_text: Optional[str] = None
    report_generated_by: Optional[str] = None
    recommended_actions: List[str] = Field(default_factory=list)
    timestamp: Optional[str] = None
    error_message: Optional[str] = None


class HealthResponse(BaseModel):
    status: str
    version: str = "0.1.0"
    database: bool
    redis: bool
    ollama: bool
    laya_available: bool
