import os
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

def get_database_url() -> str:
    url = os.getenv("DATABASE_URL")
    if not url:
        raise RuntimeError("DATABASE_URL is not set")
    # Render sometimes provides postgres:// ; SQLAlchemy prefers postgresql://
    if url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql://", 1)
    return url

ENGINE = create_engine(get_database_url(), pool_pre_ping=True)
SessionLocal = sessionmaker(bind=ENGINE)

def db_ping() -> bool:
    with ENGINE.connect() as conn:
        conn.execute(text("SELECT 1"))
    return True
