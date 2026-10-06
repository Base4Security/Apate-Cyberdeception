"""Contrato OpenAPI 3.1 para control gobernado con identidad de máquina."""


def specification():
    operations = {
        "/api/v1/operations": {"get": ("operations", "operations:read")},
        "/api/v1/operations/{operation_id}": {"get": ("operation_detail", "operations:read")},
        "/api/v1/operations/{operation_id}/telemetry": {"get": ("telemetry", "telemetry:read")},
        "/api/v1/operations/{operation_id}/control": {"get": ("control_status", "operations:read")},
        "/api/v1/operations/{operation_id}/readiness": {"get": ("operation_readiness", "operations:read")},
        "/api/v1/operations/{operation_id}/plans": {"post": ("propose_operation_plan", "plans:propose")},
        "/api/v1/operations/{operation_id}/plans/{plan_id}/activate": {"post": ("activate_operation_plan", "plans:activate")},
        "/api/v1/operations/{operation_id}/stop": {"post": ("stop_operation", "operations:stop")},
        "/api/v1/operations/{operation_id}/capabilities/{capability_id}/{action}": {"post": ("execute_capability", "capabilities:execute")},
    }
    paths = {}
    import re
    for path, methods in operations.items():
        paths[path] = {}
        for method, (identifier, scope) in methods.items():
            parameters = [{"name": name, "in": "path", "required": True,
                "schema": {"type": "string", **({"enum": ["deploy", "rotate", "retire"]} if name == "action" else {})}}
                for name in re.findall(r"\{([^}]+)\}", path)]
            if identifier == "telemetry":
                parameters += [{"name": "after", "in": "query", "schema": {"type": "integer", "minimum": 0}},
                    {"name": "limit", "in": "query", "schema": {"type": "integer", "minimum": 1, "maximum": 500}}]
            operation = {"operationId": identifier, "security": [{"machineBearer": []}],
                "x-apate-scope": scope, "parameters": parameters,
                "responses": {str(status): {"description": meaning} for status, meaning in (
                    (200, "OK"), (201, "Created"), (400, "Invalid input"), (401, "Invalid bearer"),
                    (403, "Scope denied"), (404, "Not found"), (409, "Version, policy or idempotency conflict"),
                    (429, "Rate limit"), (503, "Reconciliation required"))}}
            if method == "post":
                parameters.append({"name": "Idempotency-Key", "in": "header", "required": True,
                    "schema": {"type": "string", "minLength": 1, "maxLength": 128}})
                operation["requestBody"] = {"required": True, "content": {"application/json": {"schema": {"type": "object"}}}}
            paths[path][method] = operation
    return {"openapi": "3.1.0", "info": {"title": "APATE governed API", "version": "1"}, "paths": paths,
        "components": {"securitySchemes": {"machineBearer": {"type": "http", "scheme": "bearer"}}},
        "x-apate-human-approval-required": True, "x-apate-physical-verification": "external_gate"}
