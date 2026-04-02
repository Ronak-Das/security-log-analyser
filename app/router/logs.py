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

@router.get("/alerts")
def detect_suspicious_activity():
    ip_fail_count = {}

    # Count failed attempts per IP
    for log in logs_storage:
        if log.status == "failed":
            ip_fail_count[log.ip] = ip_fail_count.get(log.ip, 0) + 1

    # Find suspicious IPs (more than 3 failures)
    suspicious_ips = [
        {"ip": ip, "failed_attempts": count}
        for ip, count in ip_fail_count.items()
        if count > 3
    ]

    return suspicious_ips