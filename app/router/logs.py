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
def get_logs(status: str = Query(None), ip: str = Query(None)):
    filtered_logs = logs_storage

    if status:
        filtered_logs = [log for log in filtered_logs if log.status == status]

    if ip:
        filtered_logs = [log for log in filtered_logs if log.ip == ip]

    return filtered_logs