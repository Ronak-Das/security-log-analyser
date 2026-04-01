from fastapi import APIRouter , Query
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
def get_logs(status: str = Query(None)):
    if status:
        return [log for log in logs_storage if log.status == status]
    return logs_storage