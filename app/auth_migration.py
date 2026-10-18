"""Add email/session support without replacing user IDs or financial records."""
import re
from sqlalchemy import inspect, text
from .config import settings
from .database import engine, SessionLocal, Base
from .models import User
from .security import get_password_hash, verify_password


def initialize_auth():
    with engine.begin() as connection:
        if inspect(connection).has_table('users'):
            names = {c['name'] for c in inspect(connection).get_columns('users')}
            if 'email' not in names:
                connection.execute(text('ALTER TABLE users ADD COLUMN email VARCHAR(254)'))
    Base.metadata.create_all(bind=engine)
    with engine.begin() as connection:
        connection.execute(text('CREATE UNIQUE INDEX IF NOT EXISTS ux_users_email ON users (email)'))

    configured = [x for x in (settings.OWNER_EMAIL, settings.ADMIN_EMAIL) if x]
    if len(configured) != len(set(configured)):
        raise RuntimeError('Email Owner dan Admin harus berbeda.')
    if settings.OWNER_INITIAL_PASSWORD and settings.OWNER_INITIAL_PASSWORD == settings.ADMIN_INITIAL_PASSWORD:
        raise RuntimeError('Password awal Owner dan Admin harus berbeda.')
    with SessionLocal() as db:
        for role, username, name, email, password in (
            ('owner', settings.DEFAULT_OWNER_USERNAME, settings.DEFAULT_OWNER_NAME, settings.OWNER_EMAIL, settings.OWNER_INITIAL_PASSWORD),
            ('admin', settings.DEFAULT_ADMIN_USERNAME, settings.DEFAULT_ADMIN_NAME, settings.ADMIN_EMAIL, settings.ADMIN_INITIAL_PASSWORD),
        ):
            user = db.query(User).filter(User.username == username).first()
            if user is not None and user.role != role:
                raise RuntimeError('Identitas akun tidak cocok dengan peran migrasi.')
            if user is not None and user.email:
                continue  # Never change an enrolled email, password or activation on restart.
            if not email and not password:
                continue  # Legacy account cannot sign in until explicitly enrolled.
            if not re.fullmatch(r'[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+', email):
                raise RuntimeError(f'Email {role} belum valid.')
            if len(password) < 12 or len(password.encode('utf-8')) > 72:
                raise RuntimeError(f'Password awal {role} harus minimal 12 karakter dan maksimal 72 byte.')
            if db.query(User).filter(User.email == email).first():
                raise RuntimeError('Email akun telah digunakan.')
            if user is not None and verify_password(password, user.hashed_password):
                raise RuntimeError(f'Gunakan password awal {role} yang berbeda dari password lama.')
            if user is None:
                user = User(username=username, role=role, full_name=name, is_active=True)
                db.add(user)
            user.email = email
            user.hashed_password = get_password_hash(password)
        db.flush()
        if not settings.DEBUG and db.query(User).filter(User.role=='owner', User.email.is_not(None)).first() is None:
            raise RuntimeError('Owner belum disiapkan. Atur email dan password awal Owner melalui konfigurasi aman.')
        db.commit()
