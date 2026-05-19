from __future__ import annotations

import os
import sys
from pathlib import Path

# Ensure repo root is on sys.path for `from app...` imports.
REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# Set env vars before any app module is imported (app.db reads DATABASE_URL
# at import time; auth_and_rls reads ANCHOR_JWT_SECRET).
os.environ.setdefault(
    "DATABASE_URL", "postgresql://anchor:anchor@localhost/anchor_test"
)
os.environ.setdefault("RATE_LIMIT_ENABLED", "0")
os.environ.setdefault("RATE_LIMIT_SECRET", "test-secret")
os.environ.setdefault("ANCHOR_JWT_SECRET", "test-jwt-secret")
os.environ.setdefault("ANCHOR_AUTH_STRICT_DB_CHECK", "0")
