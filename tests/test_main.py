from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_root(client):
    response = client.get("/")

    assert response.status_code == 200
    assert response.json() == {
        "message": "Security Log analyser is running"
    }
    
def test_ingest_log(client):
    log_data = {
        "timestamp": "2026-11-09T15:00:00",
        "ip": "192.168.1.100",
        "username": "pytest_user",
        "status": "failed"
    }

    response = client.post("/logs", json=log_data)

    assert response.status_code == 200
    assert response.json() == {
        "message": "log stored successfully"
    }

    # Verify that the log was actually stored
    get_response = client.get("/logs")

    assert get_response.status_code == 200
    assert len(get_response.json()) == 1
    assert get_response.json()[0]["username"] == "pytest_user"
    
def test_filter_logs(client):
    logs = [
        {
            "timestamp": "2026-11-09T15:00:00",
            "ip": "192.168.1.100",
            "username": "user1",
            "status": "failed"
        },
        {
            "timestamp": "2026-11-09T15:01:00",
            "ip": "192.168.1.101",
            "username": "user2",
            "status": "success"
        },
        {
            "timestamp": "2026-11-09T15:02:00",
            "ip": "192.168.1.100",
            "username": "user3",
            "status": "failed"
        }
    ]

    for log in logs:
        client.post("/logs", json=log)

    response = client.get(
        "/logs",
        params={
            "status": "failed",
            "ip": "192.168.1.100"
        }
    )

    assert response.status_code == 200
    assert len(response.json()) == 2

    for log in response.json():
        assert log["status"] == "failed"
        assert log["ip"] == "192.168.1.100"
        
def test_rate_based_detection(client):
    for i in range(5):
        log_data = {
            "timestamp": "2026-11-09T15:00:00",
            "ip": "192.168.1.200",
            "username": f"user{i}",
            "status": "failed"
        }

        client.post("/logs", json=log_data)

    response = client.get(
        "/alerts/rate",
        params={
            "seconds": 60,
            "threshold": 5
        }
    )

    assert response.status_code == 200
    assert response.json()["total_suspicious"] == 1
    assert response.json()["suspicious_ips"][0]["ip"] == "192.168.1.200"
    assert response.json()["suspicious_ips"][0]["attempts"] == 5
def test_account_based_detection(client):
    test_logs = [
        {
            "timestamp": "2026-11-09T15:00:00",
            "ip": "192.168.1.201",
            "username": "target_user",
            "status": "failed"
        },
        {
            "timestamp": "2026-11-09T15:00:00",
            "ip": "192.168.1.201",
            "username": "target_user",
            "status": "failed"
        },
        {
            "timestamp": "2026-11-09T15:00:00",
            "ip": "192.168.1.201",
            "username": "target_user",
            "status": "failed"
        },
        {
            "timestamp": "2026-11-09T15:00:00",
            "ip": "192.168.1.202",
            "username": "target_user",
            "status": "failed"
        },
        {
            "timestamp": "2026-11-09T15:00:00",
            "ip": "192.168.1.202",
            "username": "target_user",
            "status": "failed"
        }
    ]

    for log in test_logs:
        client.post("/logs", json=log)

    response = client.get(
        "/alerts/account",
        params={
            "seconds": 300,
            "threshold": 5
        }
    )

    assert response.status_code == 200

    accounts = response.json()["suspicious_accounts"]

    target = next(
        account for account in accounts
        if account["username"] == "target_user"
    )

    assert target["attempts"] == 5
    assert len(target["source_ips"]) == 2
    assert set(target["source_ips"]) == {
        "192.168.1.201",
        "192.168.1.202"
    }