"""Pydantic request models for the control-plane API."""
from typing import Any, Literal

from pydantic import BaseModel, Field

# Wartości enumeracyjne renderowane wprost w atrybutach HTML (class="risk {...}").
# Ograniczenie po stronie wejścia to druga linia obrony obok escapowania.
RiskLevel = Literal["low", "medium", "high"]
ToolMode = Literal["read-only", "read-write", "write", "destructive"]


class RuntimeCreate(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    description: str = ""
    package_id: str = ""
    runtime_class: str = "http-gateway"
    template: str = "blank"
    risk_level: RiskLevel = "low"
    first_tool_name: str = ""
    first_tool_url: str = ""
    first_tool_method: str = "POST"
    first_tool_body_json: dict[str, Any] = Field(default_factory=dict)
    first_tool_enabled: bool = True


class ToolCreate(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    description: str = ""
    execution_type: str = "http_request"
    url: str
    method: str = "POST"
    body_json: dict[str, Any] = Field(default_factory=dict)
    enabled: bool = False
    risk_level: RiskLevel = "low"
    mode: ToolMode = "read-only"
    category: str = "other"


class AdapterCreate(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    description: str = ""
    adapter_type: str = "http"
    risk_level: RiskLevel = "low"
    mode: ToolMode = "read-only"
    implemented: bool = False
    enabled: bool = False
