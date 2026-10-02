import os
import pathlib
import sys
import tempfile

p = pathlib.Path(tempfile.gettempdir()) / "ainids_hist.db"
if p.exists():
    p.unlink()
os.environ.update(
    {
        "DATABASE_URL": "sqlite:///" + str(p),
        "JWT_SECRET": "x" * 32,
        "ENVIRONMENT": "test",
        "SEED_DEMO_DATA": "false",
    }
)
sys.path.insert(0, "backend")
from app.db.session import SessionLocal, init_db  # noqa: E402
from app.services import network_status_service as ns  # noqa: E402

init_db()
s = SessionLocal()
ns.set_status(s, "maintenance", reason="why not")
h = ns.history(s)
print("HISTTYPE", type(h).__name__, len(h))
print("ITEMKEYS", sorted(h[0].keys()))
print("ITEM0", {k: v for k, v in h[0].items() if "status" in k or k == "source"})
s.close()