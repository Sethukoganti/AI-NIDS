"""Fail loudly if any /api route other than auth+health has no RBAC guard."""
import inspect
import sys

sys.path.insert(0, "backend")
from fastapi.params import Depends  # noqa: E402
from fastapi.routing import APIRoute  # noqa: E402

from app.main import app  # noqa: E402

# Endpoints that are reachable without a token by design.
PUBLIC = {
    "/api/auth/login",
    "/api/auth/refresh",
    "/api/auth/logout",
    "/api/auth/me",
    "/api/health",
    "/api/health/live",
    "/api/health/system",
    "/api/health/runtime",
    "/openapi.json",
    "/docs",
    "/docs/oauth2-redirect",
    "/redoc",
    "/",
}

unguarded = []
for route in app.routes:
    if not isinstance(route, APIRoute):
        continue
    if route.path in PUBLIC:
        continue
    dep_names = []
    for dep in route.dependant.dependencies:
        call = dep.call
        dep_names.append(getattr(call, "__name__", str(call)))
        # one level of indirection for guards built from require_permission(...)
        for sub in dep.dependencies:
            dep_names.append(getattr(sub.call, "__name__", str(sub.call)))
    if not any("require" in n or "user" in n for n in dep_names):
        unguarded.append((route.path, sorted(route.methods), dep_names))

for path, methods, deps in unguarded:
    print("UNGUARDED %-52s %s  deps=%s" % (path, methods, deps))
print("total unguarded:", len(unguarded))