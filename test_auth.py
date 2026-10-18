"""Security regression tests; synthetic credentials and disposable databases only."""
import os
import sqlite3
import tempfile
from pathlib import Path
from datetime import datetime, timedelta
import bcrypt

tmp = tempfile.TemporaryDirectory()
database = Path(tmp.name)/'migration.db'
os.environ.update(DATABASE_URL='sqlite:///'+database.as_posix(), ENVIRONMENT='production',
                  PUBLIC_ORIGIN='https://cashflowkrp.onrender.com',
                  OWNER_EMAIL='owner@example.test', ADMIN_EMAIL='admin@example.test',
                  OWNER_INITIAL_PASSWORD='fixture-owner-unique-2026',
                  ADMIN_INITIAL_PASSWORD='fixture-admin-unique-2026')

# Existing pre-email schema and records, with stable user IDs.
legacy_hash=bcrypt.hashpw(b'fixture-legacy-password', bcrypt.gensalt()).decode()
with sqlite3.connect(database) as db:
    db.executescript('''CREATE TABLE users (
      id INTEGER PRIMARY KEY, username VARCHAR(50) NOT NULL UNIQUE,
      hashed_password VARCHAR(255) NOT NULL, full_name VARCHAR(100) NOT NULL,
      role VARCHAR(20) NOT NULL, is_active BOOLEAN, created_at DATETIME);
    CREATE TABLE transactions (
      id VARCHAR(36) PRIMARY KEY, date VARCHAR(10) NOT NULL, type VARCHAR(10) NOT NULL,
      category VARCHAR(100) NOT NULL, description VARCHAR(255), penyewa VARCHAR(150),
      amount FLOAT NOT NULL, created_by_id INTEGER, created_by_name VARCHAR(100), created_at DATETIME);
    ''')
    for uid, name, role in [(7,'owner','owner'),(9,'admin','admin')]:
        db.execute('INSERT INTO users VALUES (?,?,?,?,?,?,?)',(uid,name,legacy_hash,name,role,True,datetime.utcnow()))
    db.execute('INSERT INTO transactions VALUES (?,?,?,?,?,?,?,?,?,?)',
               ('fixture-transaction','2026-09-30','masuk','Pendapatan Sewa Harian','Data contoh','Penyewa contoh',8000000,7,'owner',datetime.utcnow()))

from fastapi.testclient import TestClient
from sqlalchemy import select, delete
from app.main import app
from app.database import SessionLocal, engine
from app.models import User, Transaction, AuthSession, LoginAttempt, TruckSetting
from app.security import token_hash, verify_password, get_password_hash, record_login_failure
from app.auth_migration import initialize_auth

ORIGIN='https://cashflowkrp.onrender.com'
HEADERS={'Origin': ORIGIN}

def client():
    return TestClient(app, base_url=ORIGIN)

def login(c, role='owner', password=None):
    return c.post('/api/auth/login', headers=HEADERS,
                  json={'email':role+'@example.test', 'password':password or f'fixture-{role}-unique-2026'})

owner=client()
admin=client()
anonymous=client()

with SessionLocal() as db:
    assert [(u.id,u.role,u.email) for u in db.query(User).order_by(User.id)] == [(7,'owner','owner@example.test'),(9,'admin','admin@example.test')]
    assert db.query(Transaction).one().amount == 8000000
    db.add(TruckSetting(nopol='TEST 123 KRP', jenis='Truk contoh', kapasitas='8 Ton', tahun=2024, status='Milik Sendiri', cicilan=0))
    db.commit()
print('[PASS] Additive migration preserves user IDs, roles and financial records')

assert anonymous.get('/api/dashboard').status_code==401
assert anonymous.get('/api/dashboard',headers={'Authorization':'Bearer legacy-token'}).status_code==401
assert anonymous.post('/api/auth/login',headers=HEADERS,json={'username':'owner','password':'fixture-owner-unique-2026'}).status_code==422
assert anonymous.post('/api/auth/login',json={'email':'owner@example.test','password':'fixture-owner-unique-2026'}).status_code==403
assert anonymous.post('/api/auth/login',headers={'Origin':'https://attacker.example'},json={'email':'owner@example.test','password':'fixture-owner-unique-2026'}).status_code==403
response=owner.post('/api/auth/login',headers=HEADERS,json={'email':' OWNER@EXAMPLE.TEST ','password':'fixture-owner-unique-2026'})
assert response.status_code==200, response.text
assert set(response.json())=={'user'}
cookie=response.headers['set-cookie']
assert all(x in cookie for x in ['__Host-krp_session=','HttpOnly','Secure','SameSite=lax','Path=/'])
assert 'Domain=' not in cookie
assert response.headers['cache-control']=='no-store'
raw=owner.cookies.get('__Host-krp_session')
with SessionLocal() as db:
    assert db.get(AuthSession, token_hash(raw)) is not None
    assert db.query(AuthSession).filter(AuthSession.token_hash==raw).count()==0
assert owner.get('/api/auth/me').json()['email']=='owner@example.test'
assert login(admin,'admin').status_code==200
assert admin.get('/api/backup/export').status_code==403
assert owner.get('/api/backup/export').status_code==200
assert owner.get('/api/dashboard').json()['saldo']==8000000
assert owner.get('/api/trucks').json()[0]['nopol']=='TEST 123 KRP'
assert owner.get('/api/reports/monthly?month=2026-09').json()['saldo_akhir']==8000000
assert owner.get('/api/reports/weekly?week=2026-W40').status_code==200
assert admin.post('/api/trucks',headers=HEADERS,json={'nopol':'TEST 321'}).status_code==403
assert owner.post('/api/trucks',headers={'Origin':'https://attacker.example'},json={'nopol':'TEST 321'}).status_code==403
created=admin.post('/api/transactions',headers=HEADERS,json={'date':'2026-10-18','type':'masuk','category':'Pendapatan Sewa Harian','description':'Transaksi contoh','penyewa':'Penyewa contoh','amount':2000000})
assert created.status_code==201,created.text
assert owner.get('/api/dashboard').json()['saldo']==10000000
assert owner.get('/api/reports/monthly?month=2026-10').json()['saldo_awal']==8000000
assert owner.get('/api/reports/monthly?month=2026-10').json()['saldo_akhir']==10000000
assert len(admin.get('/api/transactions').json()['transactions'])==2
truck=owner.post('/api/trucks',headers=HEADERS,json={'nopol':'TEST 321 KRP','jenis':'Truk contoh'})
assert truck.status_code==201
assert admin.delete('/api/trucks/'+str(truck.json()['id']),headers=HEADERS).status_code==403
assert owner.delete('/api/trucks/'+str(truck.json()['id']),headers=HEADERS).status_code==200
assert admin.post('/api/backup/import',headers=HEADERS,json={'transactions':[]}).status_code==403
cors=anonymous.options('/api/auth/login',headers={'Origin':'https://attacker.example','Access-Control-Request-Method':'POST'})
assert cors.status_code==400 and 'access-control-allow-origin' not in cors.headers
print('[PASS] Email login, cookie flags, bearer rejection, CSRF, CORS and owner/admin access')

for c in [client(),client()]:
    assert login(c, password='fixture-legacy-password').status_code==401
old_owner=client()
assert login(old_owner).status_code==200
r=owner.post('/api/auth/change-password',headers=HEADERS,json={'old_password':'fixture-owner-unique-2026','new_password':'fixture-owner-changed-2026'})
assert r.status_code==200,r.text
assert old_owner.get('/api/dashboard').status_code==401
assert owner.get('/api/dashboard').status_code==200
initialize_auth()
assert owner.get('/api/dashboard').status_code==200
with SessionLocal() as db:
    assert verify_password('fixture-owner-changed-2026',db.get(User,7).hashed_password)
    assert not verify_password('fixture-owner-unique-2026',db.get(User,7).hashed_password)
assert owner.post('/api/owner/admin-password',headers=HEADERS,json={'new_password':'fixture-admin-changed-2026'}).status_code==200
assert admin.get('/api/dashboard').status_code==401
assert login(admin,'admin',password='fixture-admin-changed-2026').status_code==200
token=admin.cookies.get('__Host-krp_session')
assert admin.post('/api/auth/logout',headers=HEADERS).status_code==200
assert admin.get('/api/dashboard').status_code==401
stolen=client()
stolen.cookies.set('__Host-krp_session',token)
assert stolen.get('/api/dashboard').status_code==401
with SessionLocal() as db:
    session=db.get(AuthSession,token_hash(owner.cookies.get('__Host-krp_session')))
    session.expires_at=datetime.utcnow()-timedelta(seconds=1)
    db.commit()
assert owner.get('/api/dashboard').status_code==401
print('[PASS] Password persistence on restart, session rotation, reset revocation, logout replay and expiry')

bad=client()
for _ in range(10):
    assert login(bad,'admin',password='wrong-fixture').status_code==401
assert login(bad,'admin',password='fixture-admin-changed-2026').status_code==429
with SessionLocal() as db:
    # The limit is persisted, not reset by an application restart.
    assert db.query(LoginAttempt).count()>0
initialize_auth()
assert login(bad,'admin',password='fixture-admin-changed-2026').status_code==429
with SessionLocal() as db:
    db.execute(delete(LoginAttempt)); db.commit()
assert login(owner,password='fixture-owner-changed-2026').status_code==200
secret='x'*73
r=owner.post('/api/auth/change-password',headers=HEADERS,json={'old_password':'fixture-owner-changed-2026','new_password':secret})
assert r.status_code==422 and secret not in r.text
try:
    get_password_hash('é'*40)
    raise AssertionError('UTF-8 password was truncated')
except ValueError:
    pass
assert verify_password('é'*40,legacy_hash)==False
with SessionLocal() as db:
    user=db.get(User,7); user.is_active=False; db.commit()
assert owner.get('/api/dashboard').status_code==401
assert login(client(),password='fixture-owner-changed-2026').status_code==401
print('[PASS] Durable login limits, password length handling, safe validation and disabled accounts')
print('ALL AUTH SECURITY TESTS PASSED (DISPOSABLE SYNTHETIC DATABASE)')
for c in [owner,admin,anonymous,bad,old_owner,stolen]:
    c.close()
engine.dispose()
tmp.cleanup()
