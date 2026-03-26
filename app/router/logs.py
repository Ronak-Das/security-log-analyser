from fastapi import APIRouter
from app.models.log_model import Log

logs_storage = []

router = APIRouter()

@router.post("/logs")
def ingest_log(log: Log):
    
    logs_storage.append(log)
    return {
        "message": "log stored successfully"
    }

@router.get("/logs")
def get_logs():
    return logs_storage