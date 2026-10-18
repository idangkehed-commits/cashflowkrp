import hashlib
import secrets
from datetime import datetime, timedelta
import bcrypt
from fastapi import Depends, HTTPException, Request
from sqlalchemy import delete, case
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.dialects.postgresql import insert as postgres_insert
from sqlalchemy.orm import Session
from .config import settings
from .database import get_db
from .models import User, AuditLog, AuthSession, LoginAttempt


def verify_password(password, hashed):
    raw = password.encode('utf-8')
    if len(raw) > 72:
        return False
    try:
        return bcrypt.checkpw(raw, hashed.encode('utf-8'))
    except (ValueError, TypeError):
        return False


def get_password_hash(password):
    raw = password.encode('utf-8')
    if len(raw) > 72:
        raise ValueError('Password maksimal 72 byte UTF-8.')
    return bcrypt.hashpw(raw, bcrypt.gensalt()).decode('utf-8')


DUMMY_HASH = get_password_hash('dummy-account-never-used-for-login')


def token_hash(token):
    return hashlib.sha256(token.encode('utf-8')).hexdigest()


def set_session(db, user, response):
    now = datetime.utcnow()
    db.execute(delete(AuthSession).where(AuthSession.expires_at <= now))
    token = secrets.token_urlsafe(32)
    db.add(AuthSession(token_hash=token_hash(token), user_id=user.id,
                       expires_at=now + timedelta(minutes=settings.SESSION_MINUTES)))
    db.commit()
    response.set_cookie(settings.COOKIE_NAME, token, max_age=settings.SESSION_MINUTES*60,
                        path='/', secure=not settings.DEBUG, httponly=True, samesite='lax')


def clear_session(request, response, db):
    token = request.cookies.get(settings.COOKIE_NAME)
    if token:
        db.execute(delete(AuthSession).where(AuthSession.token_hash == token_hash(token)))
        db.commit()
    response.delete_cookie(settings.COOKIE_NAME, path='/', secure=not settings.DEBUG,
                           httponly=True, samesite='lax')


def revoke_user_sessions(db, user_id):
    db.execute(delete(AuthSession).where(AuthSession.user_id == user_id))


def get_current_user(request: Request, db: Session = Depends(get_db)):
    token = request.cookies.get(settings.COOKIE_NAME, '')
    if not token or len(token) > 128:
        raise HTTPException(401, 'Silakan masuk kembali dengan email dan password.')
    session = db.query(AuthSession).filter(AuthSession.token_hash == token_hash(token),
                                         AuthSession.expires_at > datetime.utcnow()).first()
    user = db.get(User, session.user_id) if session else None
    if user is None or not user.is_active or not user.email:
        raise HTTPException(401, 'Sesi tidak valid atau telah berakhir. Silakan masuk kembali.')
    return user


def require_owner(current_user: User = Depends(get_current_user)):
    if current_user.role != 'owner':
        raise HTTPException(403, 'Akses ditolak: fitur ini hanya untuk Owner.')
    return current_user


def require_same_origin(request):
    allowed = {settings.PUBLIC_ORIGIN}
    if settings.DEBUG:
        allowed.add(str(request.base_url).rstrip('/'))
    if request.headers.get('origin') not in allowed:
        raise HTTPException(403, 'Permintaan harus berasal dari aplikasi KRP.')


def login_keys(email, ip):
    return [(token_hash('account:'+email), 10), (token_hash('ip:'+ip), 30)]


def check_login_limits(db, email, ip):
    now = datetime.utcnow()
    for key, maximum in login_keys(email, ip):
        attempt = db.get(LoginAttempt, key)
        if attempt and attempt.window_start > now-timedelta(minutes=15) and attempt.failures >= maximum:
            raise HTTPException(429, 'Terlalu banyak percobaan masuk. Coba lagi dalam 15 menit.', headers={'Retry-After':'900'})


def record_login_failure(db, email, ip):
    now = datetime.utcnow()
    cutoff = now-timedelta(minutes=15)
    insert = sqlite_insert if db.bind.dialect.name == 'sqlite' else postgres_insert
    for key, _ in login_keys(email, ip):
        stmt = insert(LoginAttempt).values(key=key, failures=1, window_start=now)
        stmt = stmt.on_conflict_do_update(index_elements=['key'], set_={
            'failures': case((LoginAttempt.window_start <= cutoff, 1), else_=LoginAttempt.failures+1),
            'window_start': case((LoginAttempt.window_start <= cutoff, now), else_=LoginAttempt.window_start),
        })
        db.execute(stmt)
    db.commit()


def reset_account_attempts(db, email):
    db.execute(delete(LoginAttempt).where(LoginAttempt.key == token_hash('account:'+email)))
    db.commit()


def log_audit(db, request, action, details, user=None):
    try:
        db.add(AuditLog(user_id=user.id if user else None,
                       username=user.username if user else 'anonymous',
                       action=action, details=details,
                       ip_address=request.client.host if request.client else 'unknown'))
        db.commit()
    except Exception:
        db.rollback()
