from fastapi import FastAPI
from app.router import logs

app= FastAPI(title="Security Log Analyser")
app.include_router(logs.router)

@app.get("/")
def root():
 return {"message: Security Log analyser is running"}
