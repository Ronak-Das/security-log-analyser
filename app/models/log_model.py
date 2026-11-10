from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime
from typing import Literal
from app.db import Base
from ipaddress import ip_address
from pydantic import BaseModel, field_validator, Field



class Log(BaseModel):
    timestamp: datetime
    ip: str
    username: str = Field(min_length=1, max_length=100)
    status: Literal["success","failed"]
    @field_validator("ip")
    @classmethod
    def validate_ip(cls, value: str) -> str:
        try:
            ip_address(value)
        except ValueError:
            raise ValueError("Invalid IP address")

        return value
    @field_validator("username", mode="before")
    @classmethod
    def validate_username(cls, value):
        if isinstance(value, str):
            return value.strip()
        return value

    


class LogDB(Base):
    __tablename__ = "logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime)
    ip = Column(String)
    username = Column(String)
    status = Column(String)