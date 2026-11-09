from fastapi import APIRouter, Query, Depends
from app.db import get_db
from app.models.log_model import Log, LogDB
from collections import defaultdict


router = APIRouter()
@router.post("/logs")
def ingest_log(log: Log, db = Depends(get_db)):

    db_log = LogDB(
        timestamp=log.timestamp,
        ip=log.ip,
        username=log.username,
        status=log.status
    )

    db.add(db_log)
    db.commit()
    db.refresh(db_log)

    return {
        "message": "log stored successfully"
    }
@router.get("/logs")
def get_logs(
    status: str = Query(None),
    ip: str = Query(None),
    db = Depends(get_db)
):
    query = db.query(LogDB)

    if status:
        query = query.filter(LogDB.status == status)

    if ip:
        query = query.filter(LogDB.ip == ip)

    logs = query.all()

    return logs

@router.get("/alerts/rate")
def detect_rate_based_attack(
    seconds: int = Query(60),
    threshold: int = Query(5),
    db = Depends(get_db)
):
    logs = db.query(LogDB).all()

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
    
@router.get("/alerts/account")
def detect_account_attack(
    seconds: int = Query(300, gt=0),
    threshold: int = Query(5, ge=1),
    db = Depends(get_db)
):
    logs = db.query(LogDB).filter(
        LogDB.status == "failed"
    ).all()

    username_logs = defaultdict(list)

    # Group failed login attempts by username
    for log in logs:
        username_logs[log.username].append(log)

    suspicious_accounts = []

    # Check each username for repeated failed attempts
    for username, attempts in username_logs.items():

        attempts.sort(key=lambda log: log.timestamp)

        for i in range(len(attempts)):
            count = 1
            source_ips = {attempts[i].ip}
            start_time = attempts[i].timestamp

            for j in range(i + 1, len(attempts)):
                elapsed = (
                    attempts[j].timestamp - start_time
                ).total_seconds()

                if elapsed > seconds:
                    break

                count += 1
                source_ips.add(attempts[j].ip)

                if count >= threshold:
                    suspicious_accounts.append({
                        "username": username,
                        "attempts": count,
                        "source_ips": sorted(source_ips),
                        "window_seconds": seconds
                    })
                    break

            if count >= threshold:
                break

    return {
        "suspicious_accounts": suspicious_accounts,
        "total_suspicious": len(suspicious_accounts),
        "config": {
            "threshold": threshold,
            "window_seconds": seconds
        }
    }