from fastapi import APIRouter , Query
from app.models.log_model import Log
from datetime import datetime, timedelta
from collections import defaultdict
from app.db import SessionLocal
from app.models.log_model import Log, LogDB


router = APIRouter()

@router.post("/logs")
def ingest_log(log: Log):

    db = SessionLocal()

    db_log = LogDB(
        timestamp=log.timestamp,
        ip=log.ip,
        username=log.username,
        status=log.status
    )

    db.add(db_log)
    db.commit()
    db.close()

    return {
        "message": "log stored successfully"
    }

@router.get("/logs")
def get_logs(status: str = Query(None), ip: str = Query(None)):
    db = SessionLocal()

    query = db.query(LogDB)

    if status:
        query = query.filter(LogDB.status == status)

    if ip:
        query = query.filter(LogDB.ip == ip)

    logs = query.all()

    db.close()

    return logs

@router.get("/alerts/rate")

def detect_rate_based_attack(
    seconds: int = Query(60),
    threshold: int = Query(5)
):
    db = SessionLocal()

    logs = db.query(LogDB).all()

    db.close()

    ip_logs = defaultdict(list)

    # Collect failed logs per IP
    for log in logs:
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
    