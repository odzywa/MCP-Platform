"""Pydantic request models for the control-plane API."""
from typing import Any

from pydantic import BaseModel, Field


class RuntimeCreate(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    description: str = ""
    package_id: str = ""
    runtime_class: str = "http-gateway"
    template: str = "blank"
    risk_level: str = "low"
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
    risk_level: str = "low"
    mode: str = "read-only"
    category: str = "other"


class AdapterCreate(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    description: str = ""
    adapter_type: str = "http"
    risk_level: str = "low"
    mode: str = "read-only"
    implemented: bool = False
    enabled: bool = False
