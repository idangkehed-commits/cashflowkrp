import uuid
from datetime import datetime
from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from .database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(254), nullable=True)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(100), nullable=False)
    role = Column(String(20), nullable=False, default="admin")  # "owner" atau "admin"
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

class AuthSession(Base):
    __tablename__ = 'auth_sessions'
    token_hash = Column(String(64), primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False, index=True)
    expires_at = Column(DateTime, nullable=False, index=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

class LoginAttempt(Base):
    __tablename__ = 'auth_login_attempts'
    key = Column(String(64), primary_key=True)
    failures = Column(Integer, nullable=False, default=0)
    window_start = Column(DateTime, nullable=False, default=datetime.utcnow)

class Transaction(Base):
    __tablename__ = "transactions"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    date = Column(String(10), index=True, nullable=False)  # Format: YYYY-MM-DD
    type = Column(String(10), index=True, nullable=False)  # "masuk" atau "keluar"
    category = Column(String(100), index=True, nullable=False)
    description = Column(String(255), nullable=True)
    penyewa = Column(String(150), nullable=True)
    amount = Column(Float, nullable=False)
    created_by_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_by_name = Column(String(100), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

class TruckSetting(Base):
    __tablename__ = "truck_settings"

    id = Column(Integer, primary_key=True, index=True)
    nopol = Column(String(30), nullable=True)
    jenis = Column(String(50), nullable=True)
    kapasitas = Column(String(50), nullable=True)
    tahun = Column(Integer, nullable=True)
    status = Column(String(50), nullable=True)
    cicilan = Column(Float, default=0.0)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=True)
    username = Column(String(50), nullable=True)
    action = Column(String(50), nullable=False)  # e.g. "LOGIN_SUCCESS", "CREATE_TRX", "DELETE_TRX"
    details = Column(String(255), nullable=True)
    ip_address = Column(String(45), nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
