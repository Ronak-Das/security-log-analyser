from pydantic import BaseModel
from datetime import datetime

class Log(BaseModel):
    timestamp: datetime
    ip: str
    username: str
    status: str