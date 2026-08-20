from fastapi import FastAPI
from app.router import logs
from app.db import Base, engine
from app.models.log_model import LogDB

Base.metadata.create_all(bind=engine)

app= FastAPI(title="Security Log Analyser")
app.include_router(logs.router)

@app.get("/")
def root():
 return {"message: Security Log analyser is running"}
