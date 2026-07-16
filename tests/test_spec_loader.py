from apisec.spec_loader import extract_endpoints

MINI_SPEC = {
    "openapi": "3.0.0",
    "paths": {
        "/users/{id}": {
            "parameters": [{"name": "id", "in": "path", "required": True, "schema": {"type": "integer"}}],
            "get": {"operationId": "getUser", "responses": {"200": {}}},
            "put": {
                "operationId": "updateUser",
                "requestBody": {
                    "content": {"application/json": {"schema": {"type": "object", "properties": {"name": {}}}}}
                },
                "responses": {"200": {}},
            },
        },
        "/health": {
            "get": {"operationId": "healthCheck", "responses": {"200": {}}},
        },
    },
}


def test_extract_endpoints_flattens_all_methods():
    endpoints = extract_endpoints(MINI_SPEC)
    methods_by_path = {}
    for e in endpoints:
        methods_by_path.setdefault(e.path, set()).add(e.method)

    assert methods_by_path["/users/{id}"] == {"GET", "PUT"}
    assert methods_by_path["/health"] == {"GET"}


def test_path_parameters_are_inherited_by_operations():
    endpoints = extract_endpoints(MINI_SPEC)
    get_user = next(e for e in endpoints if e.path == "/users/{id}" and e.method == "GET")
    assert any(p["name"] == "id" for p in get_user.parameters)


def test_request_body_schema_is_extracted():
    endpoints = extract_endpoints(MINI_SPEC)
    update_user = next(e for e in endpoints if e.path == "/users/{id}" and e.method == "PUT")
    assert update_user.request_body_schema == {"type": "object", "properties": {"name": {}}}
