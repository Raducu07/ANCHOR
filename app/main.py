from fastapi import FastAPI
from app.migrate import run_migrations
from app.db import db_ping

app = FastAPI(title="ANCHOR API")

@app.on_event("startup")
def on_startup():
    run_migrations()

@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/db-check")
def db_check():
    db_ping()
    return {"db": "ok"}
