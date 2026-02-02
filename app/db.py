import os
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

def get_database_url() -> str:
    url = os.getenv("DATABASE_URL")
    if not url:
        raise RuntimeError("DATABASE_URL is not set")

    # Normalize scheme from Render
    if url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql://", 1)

    # Force SQLAlchemy to use psycopg (v3), not psycopg2
    if url.startswith("postgresql://"):
        url = url.replace("postgresql://", "postgresql+psycopg://", 1)

    return url

ENGINE = create_engine(get_database_url(), pool_pre_ping=True)
SessionLocal = sessionmaker(bind=ENGINE)

def db_ping() -> bool:
    with ENGINE.connect() as conn:
        conn.execute(text("SELECT 1"))
    return True
