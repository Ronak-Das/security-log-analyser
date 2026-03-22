from fastapi import APIRouter
from app.models.log_model import Log

router = APIRouter()

@router.post("/logs")
def ingest_log(log: Log):
    return {
        "message": "Log received",
        "data": log
    }