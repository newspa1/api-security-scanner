"""Load an OpenAPI/Swagger spec (JSON or YAML, local file or URL) into a flat
list of Endpoint objects that checks can iterate over."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urljoin

import requests
import yaml


@dataclass
class Endpoint:
    path: str
    method: str
    operation_id: str | None
    parameters: list[dict] = field(default_factory=list)
    request_body_schema: dict | None = None
    security: list[dict] = field(default_factory=list)

    def url(self, base_url: str) -> str:
        return urljoin(base_url.rstrip("/") + "/", self.path.lstrip("/"))


def load_spec(source: str) -> dict:
    """Load a raw OpenAPI document from a local path or an http(s) URL."""
    if source.startswith("http://") or source.startswith("https://"):
        resp = requests.get(source, timeout=10)
        resp.raise_for_status()
        text = resp.text
    else:
        text = Path(source).read_text()

    if source.endswith(".json"):
        import json

        return json.loads(text)
    return yaml.safe_load(text)


def extract_endpoints(spec: dict) -> list[Endpoint]:
    """Flatten an OpenAPI 3.x `paths` object into a list of Endpoints.

    NOTE: this currently assumes OpenAPI 3.x. Swagger 2.0 (`swagger: "2.0"`)
    has a slightly different shape for request bodies and security schemes —
    add a branch here if you need to support it.
    """
    endpoints: list[Endpoint] = []
    for path, path_item in spec.get("paths", {}).items():
        shared_params = path_item.get("parameters", [])
        for method, operation in path_item.items():
            # A path item mixes operation keys (get/post/...) with non-operation
            # keys (parameters/summary/description/servers/$ref); this guard keeps
            # only real HTTP verbs. We scope to the five verbs that carry the
            # OWASP API Top 10 attack surface and deliberately omit head/options/
            # trace for the MVP. Follow-up: add "trace" here + a check for it, since
            # an endpoint accepting TRACE enables Cross-Site Tracing (XST).
            if method.lower() not in {"get", "post", "put", "patch", "delete"}:
                continue
            endpoints.append(
                Endpoint(
                    path=path,
                    method=method.upper(),
                    operation_id=operation.get("operationId"),
                    parameters=shared_params + operation.get("parameters", []),
                    request_body_schema=_extract_request_body_schema(operation),
                    security=operation.get("security", spec.get("security", [])),
                )
            )
    return endpoints


def _extract_request_body_schema(operation: dict) -> dict | None:
    body = operation.get("requestBody")
    if not body:
        return None
    content = body.get("content", {})
    json_content = content.get("application/json")
    if not json_content:
        return None
    return json_content.get("schema")
