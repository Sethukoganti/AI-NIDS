import sys

sys.path.insert(0, "backend")
from app.main import app  # noqa: E402

REQUIRED = [
    "/api/admin/users",
    "/api/admin/network/config",
    "/api/admin/network/status",
    "/api/admin/detection/config",
    "/api/admin/alerts/config",
    "/api/admin/model/config",
    "/api/admin/datasets",
    "/api/admin/settings",
    "/api/admin/audit-logs",
    "/api/admin/system/health",
    "/api/analyst/traffic/analyze",
    "/api/analyst/predictions",
    "/api/analyst/alerts",
    "/api/analyst/investigations",
    "/api/analyst/assistant",
]

present = set()
for r in app.routes:
    if hasattr(r, "methods"):
        present.add(r.path)

missing = [p for p in REQUIRED if p not in present]
for p in REQUIRED:
    print(("  OK  " if p in present else "MISS  ") + p)
print()
print("missing:", missing or "none")