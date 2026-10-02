import sys

sys.path.insert(0, "backend")
from app.api import admin, analyst, health, predictions  # noqa: E402

for mod in (admin, analyst, predictions, health):
    print("==", mod.router.prefix, "==")
    for r in mod.router.routes:
        print("  %-52s %-6s %s" % (r.path, sorted(r.methods)[0], r.name))