from fastapi import APIRouter , Query
from app.models.log_model import Log
from datetime import datetime, timedelta
from collections import defaultdict

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

@router.get("/alerts/rate")

def detect_rate_based_attack(
    seconds: int = Query(60),
    threshold: int = Query(5)
):
    
    ip_logs = defaultdict(list)
    
# Collect failed logs per IP
    for log in logs_storage:
        if log.status == "failed":
            ip_logs[log.ip].append(log.timestamp)
    
    suspicious_ips = []
    
# Check burst activity
    for ip, timestamps in ip_logs.items():
        # Sort timestamps
        timestamps.sort()

        for i in range(len(timestamps)):
            count = 1
            start_time = timestamps[i]

            for j in range(i + 1, len(timestamps)):
                if (timestamps[j] - start_time).total_seconds() <= seconds:
                    count += 1

                if count >= threshold:
                    suspicious_ips.append({
                        "ip": ip,
                        "attempts": count,
                        "window_seconds": seconds
                    })
                    break

            if count >= threshold:
                break

    return {
        "suspicious_ips": suspicious_ips,
        "total_suspicious": len(suspicious_ips),
        
        "config": {
            "threshold": threshold,
            "window_seconds": seconds
        }
    }
    