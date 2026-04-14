from fastapi import APIRouter , Query
from app.models.log_model import Log
from datetime import datetime, timedelta

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
def detect_suspicious_activity(
    minutes: int = 10,
    threshold: int = 3
):
    ip_fail_count = {}
    
    # Define time window (last 1 minute)
    time_threshold = datetime.now() - timedelta(minutes=minutes)

    # Count failed attempts per IP
    for log in logs_storage:
        if log.status == "failed" and log.timestamp >= time_threshold:
            ip_fail_count[log.ip] = ip_fail_count.get(log.ip, 0) + 1
            
    # Find suspicious IPs (more than 3 failures)
    suspicious_ips = [
        {"ip": ip, "failed_attempts": count}
        for ip, count in ip_fail_count.items()
        if count > threshold
    ]

    return {
    "suspicious_ips": suspicious_ips,
    "total_suspicious": len(suspicious_ips)
}