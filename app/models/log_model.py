from pydantic import BaseModel
from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime

from app.db import Base

class Log(BaseModel):
    timestamp: datetime
    ip: str
    username: str
    status: str
    


class LogDB(Base):
    __tablename__ = "logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime)
    ip = Column(String)
    username = Column(String)
    status = Column(String)