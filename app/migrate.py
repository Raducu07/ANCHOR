from pathlib import Path
from sqlalchemy import text
from app.db import ENGINE

def run_migrations() -> None:
    schema_path = Path(__file__).parent / "schema.sql"
    sql = schema_path.read_text(encoding="utf-8")
    with ENGINE.begin() as conn:
        conn.execute(text(sql))
