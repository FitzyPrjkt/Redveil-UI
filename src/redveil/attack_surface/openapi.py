"""OpenAPI parser — imports openapi.yaml/json into ApplicationModel (A3).

Passive, no wire. Reuses the same Endpoint/Parameter model as AttackSurfaceMapper.
Supports OpenAPI 3.x (paths → methods → parameters) and Swagger 2.0 (paths).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

from redveil.attack_surface.endpoint import Endpoint
from redveil.attack_surface.model import ApplicationModel
from redveil.attack_surface.parameter import Parameter, ParamLocation


def _param_location(openapi_in: str) -> ParamLocation:
    mapping = {
        "query": ParamLocation.QUERY,
        "path": ParamLocation.PATH,
        "header": ParamLocation.HEADER,
        "cookie": ParamLocation.COOKIE,
        "body": ParamLocation.BODY,
    }
    return mapping.get(openapi_in.lower(), ParamLocation.QUERY)


def parse_openapi_spec(spec: dict[str, Any]) -> list[Endpoint]:
    """Parse an OpenAPI spec dict into Endpoint list."""
    endpoints: list[Endpoint] = []
    paths = spec.get("paths", {})
    if not isinstance(paths, dict):
        return endpoints
    for raw_path, methods in paths.items():
        if not isinstance(methods, dict):
            continue
        if not raw_path.startswith("/"):
            raw_path = "/" + raw_path
        for method, details in methods.items():
            m = method.upper()
            if m not in {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}:
                continue
            params: list[Parameter] = []
            # Path-level parameters
            for p in details.get("parameters", []) if isinstance(details, dict) else []:
                if not isinstance(p, dict):
                    continue
                name = p.get("name")
                loc = p.get("in", "query")
                if name:
                    params.append(Parameter(name=name, location=_param_location(loc)))
            # Extract {id} from path
            import re

            for mm in re.finditer(r"\{(\w+)\}", raw_path):
                if not any(pr.name == mm.group(1) for pr in params):
                    params.append(Parameter(name=mm.group(1), location=ParamLocation.PATH))
            endpoints.append(
                Endpoint(
                    method=m,
                    path=raw_path,
                    parameters=tuple(params),
                    source="openapi",
                )
            )
    return endpoints


def load_openapi_file(path: str | Path) -> list[Endpoint]:
    """Load openapi.yaml/json from disk and parse."""
    p = Path(path).expanduser()
    if not p.exists():
        raise FileNotFoundError(f"openapi spec not found: {p}")
    text = p.read_text(encoding="utf-8")
    spec: dict[str, Any]
    if p.suffix.lower() in (".yaml", ".yml"):
        spec = yaml.safe_load(text) or {}
    else:
        spec = json.loads(text)
    return parse_openapi_spec(spec)


def load_openapi_url_content(content: str, fmt: str = "yaml") -> list[Endpoint]:
    """Parse spec from string content (for API upload, fmt yaml/json)."""
    spec: dict[str, Any]
    if fmt.lower() == "json":
        spec = json.loads(content)
    else:
        spec = yaml.safe_load(content) or {}
    return parse_openapi_spec(spec)


def merge_into_model(model: ApplicationModel, endpoints: list[Endpoint]) -> int:
    """Merge endpoints into model, dedup by (method, path). Returns added count."""
    added = 0
    seen = {(e.method.upper(), e.path) for e in model.endpoints}
    for ep in endpoints:
        key = (ep.method.upper(), ep.path)
        if key not in seen:
            model.add_endpoint(ep)
            seen.add(key)
            added += 1
    return added
