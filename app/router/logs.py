from fastapi import APIRouter

router = APIRouter()

@router.post("/logs")
def ingest_log(log: dict):
    return {
        "message": "Log received",
        "data": log
    }