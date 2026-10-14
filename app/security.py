import time
from datetime import datetime, timedelta
from typing import Optional, List, Dict
import bcrypt
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from sqlalchemy.orm import Session

from .config import settings
from .database import get_db
from .models import User, AuditLog

# HTTP Bearer Auth Scheme
security_bearer = HTTPBearer(auto_error=False)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        pwd_bytes = plain_password.encode("utf-8")[:72]
        hashed_bytes = hashed_password.encode("utf-8")
        return bcrypt.checkpw(pwd_bytes, hashed_bytes)
    except Exception:
        return False

def get_password_hash(password: str) -> str:
    pwd_bytes = password.encode("utf-8")[:72]
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(pwd_bytes, salt).decode("utf-8")

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt

# ============================================================
# IN-MEMORY RATE LIMITER FOR BRUTE FORCE PROTECTION
# ============================================================
class LoginRateLimiter:
    def __init__(self):
        # Format: { ip_address: [timestamp1, timestamp2, ...] }
        self.failed_attempts: Dict[str, List[float]] = {}
        # Format: { ip_address: lockout_until_timestamp }
        self.lockouts: Dict[str, float] = {}

    def is_blocked(self, ip: str) -> tuple[bool, int]:
        now = time.time()
        # Check active lockout
        if ip in self.lockouts:
            remaining = int(self.lockouts[ip] - now)
            if remaining > 0:
                return True, remaining
            else:
                del self.lockouts[ip]
                self.failed_attempts.pop(ip, None)

        return False, 0

    def record_failure(self, ip: str):
        now = time.time()
        window = 300  # 5 menit
        # Clean older attempts
        attempts = [t for t in self.failed_attempts.get(ip, []) if now - t < window]
        attempts.append(now)
        self.failed_attempts[ip] = attempts

        if len(attempts) >= settings.LOGIN_MAX_ATTEMPTS:
            # Lockout for 15 minutes
            self.lockouts[ip] = now + (settings.LOGIN_LOCKOUT_MINUTES * 60)
            self.failed_attempts.pop(ip, None)

    def record_success(self, ip: str):
        self.failed_attempts.pop(ip, None)
        self.lockouts.pop(ip, None)

login_limiter = LoginRateLimiter()

# ============================================================
# AUTHENTICATION & RBAC DEPENDENCIES
# ============================================================
def get_current_user(
    auth: Optional[HTTPAuthorizationCredentials] = Depends(security_bearer),
    db: Session = Depends(get_db)
) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Sesi telah kedaluwarsa atau belum login. Silakan login kembali.",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if not auth or not auth.credentials:
        raise credentials_exception

    token = auth.credentials
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = db.query(User).filter(User.username == username, User.is_active == True).first()
    if user is None:
        raise credentials_exception
    return user

def require_owner(current_user: User = Depends(get_current_user)) -> User:
    """Only allow Owner role."""
    if current_user.role != "owner":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Akses ditolak: Fitur ini hanya dapat diakses oleh Owner."
        )
    return current_user

def log_audit(db: Session, request: Request, action: str, details: str, user: Optional[User] = None):
    """Save an immutable audit record for security tracing."""
    try:
        client_ip = request.client.host if request.client else "unknown"
        # Forwarded for proxy (Render load balancer)
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            client_ip = forwarded.split(",")[0].strip()

        log_entry = AuditLog(
            user_id=user.id if user else None,
            username=user.username if user else "anonymous",
            action=action,
            details=details,
            ip_address=client_ip
        )
        db.add(log_entry)
        db.commit()
    except Exception:
        db.rollback()
