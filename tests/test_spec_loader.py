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


# ---- security extraction: three distinct states, not two ---------------------
# (declared-public [] vs no-information-at-all None vs an actual scheme list)

SECURITY_SPEC = {
    "openapi": "3.0.0",
    "paths": {
        "/public": {"get": {"operationId": "getPublic", "security": [], "responses": {"200": {}}}},
        "/protected": {
            "get": {
                "operationId": "getProtected",
                "security": [{"bearerAuth": []}],
                "responses": {"200": {}},
            }
        },
        "/no-info": {"get": {"operationId": "getNoInfo", "responses": {"200": {}}}},
        "/inherits-global": {"get": {"operationId": "getInherited", "responses": {"200": {}}}},
    },
}


def test_explicit_empty_security_extracts_as_empty_list():
    endpoints = extract_endpoints(SECURITY_SPEC)
    ep = next(e for e in endpoints if e.path == "/public")
    assert ep.security == []


def test_explicit_scheme_is_extracted():
    endpoints = extract_endpoints(SECURITY_SPEC)
    ep = next(e for e in endpoints if e.path == "/protected")
    assert ep.security == [{"bearerAuth": []}]


def test_no_security_anywhere_extracts_as_none_not_empty_list():
    # No operation-level `security`, and the spec declares no global default
    # either -> genuinely "no information", must NOT collapse to [].
    endpoints = extract_endpoints(SECURITY_SPEC)
    ep = next(e for e in endpoints if e.path == "/no-info")
    assert ep.security is None


def test_operation_without_security_inherits_spec_global_default():
    spec_with_global = {**SECURITY_SPEC, "security": [{"apiKeyAuth": []}]}
    endpoints = extract_endpoints(spec_with_global)
    ep = next(e for e in endpoints if e.path == "/inherits-global")
    assert ep.security == [{"apiKeyAuth": []}]
