import os
from datetime import datetime, date, timedelta
from typing import Optional, List
from fastapi import FastAPI, Depends, HTTPException, status, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from sqlalchemy.orm import Session
from sqlalchemy import func

from .config import settings
from .database import engine, Base, get_db
from .models import User, Transaction, TruckSetting, AuditLog
from .schemas import (
    UserLogin, UserResponse, UserChangePassword, Token,
    TransactionCreate, TransactionResponse, TruckSettingSchema, DashboardSummary,
    AdminPasswordReset, TruckSettingCreate, TruckSettingResponse
)
from .security import (
    get_password_hash, verify_password, create_access_token,
    get_current_user, require_owner, login_limiter, log_audit
)

# Initialize Database Tables
Base.metadata.create_all(bind=engine)

def seed_initial_data():
    """Seed initial Owner, Admin, and Truck settings if not already in DB."""
    db = next(get_db())
    try:
        if db.query(User).count() == 0:
            owner = User(
                username=settings.DEFAULT_OWNER_USERNAME,
                hashed_password=get_password_hash(settings.DEFAULT_OWNER_PASSWORD),
                full_name=settings.DEFAULT_OWNER_NAME,
                role="owner",
                is_active=True
            )
            admin = User(
                username=settings.DEFAULT_ADMIN_USERNAME,
                hashed_password=get_password_hash(settings.DEFAULT_ADMIN_PASSWORD),
                full_name=settings.DEFAULT_ADMIN_NAME,
                role="admin",
                is_active=True
            )
            db.add_all([owner, admin])
            db.commit()

        if db.query(TruckSetting).count() == 0:
            truck = TruckSetting(
                nopol="B 9876 KRP",
                jenis="Truk Fuso (CDD)",
                kapasitas="8 Ton",
                tahun=2023,
                status="Milik Sendiri (Lunas)",
                cicilan=0.0
            )
            db.add(truck)
            db.commit()
    finally:
        db.close()

seed_initial_data()

# FastAPI App with production docs toggle for security
app = FastAPI(
    title="PT KYNAN RAHARJA PRATAMA - Cash Flow API",
    version="2.0.0",
    docs_url="/api/docs" if settings.DEBUG else None,
    redoc_url="/api/redoc" if settings.DEBUG else None
)

# Security Middleware: Security Headers
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response

# CORS Middleware (Restricted)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if settings.DEBUG else [
        "https://cashflowkrp.onrender.com"
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE", "PUT", "OPTIONS"],
    allow_headers=["*"],
)

# Helper Indonesian Month Names
MN_INDO = ['Januari','Februari','Maret','April','Mei','Juni','Juli','Agustus','September','Oktober','November','Desember']

# ============================================================
# AUTHENTICATION ENDPOINTS
# ============================================================
@app.post("/api/auth/login", response_model=Token)
async def login(credentials: UserLogin, request: Request, db: Session = Depends(get_db)):
    client_ip = request.client.host if request.client else "unknown"
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        client_ip = forwarded.split(",")[0].strip()

    # 1. Rate Limiting Check (Brute-Force Protection)
    is_blocked, remaining_seconds = login_limiter.is_blocked(client_ip)
    if is_blocked:
        remaining_minutes = max(1, remaining_seconds // 60)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Terlalu banyak percobaan login gagal. Akun diblokir sementara demi keamanan selama {remaining_minutes} menit."
        )

    # 2. Query User
    user = db.query(User).filter(User.username == credentials.username.strip()).first()
    if not user or not verify_password(credentials.password, user.hashed_password):
        login_limiter.record_failure(client_ip)
        log_audit(db, request, "LOGIN_FAILED", f"Username: {credentials.username}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Username atau password salah."
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Akun ini telah dinonaktifkan."
        )

    # 3. Success: Reset rate limit & Issue JWT
    login_limiter.record_success(client_ip)
    log_audit(db, request, "LOGIN_SUCCESS", f"Role: {user.role}", user)

    access_token = create_access_token(
        data={"sub": user.username, "role": user.role, "uid": user.id}
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": user
    }

@app.get("/api/auth/me", response_model=UserResponse)
async def get_me(current_user: User = Depends(get_current_user)):
    return current_user

@app.post("/api/auth/change-password")
async def change_password(
    data: UserChangePassword,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not verify_password(data.old_password, current_user.hashed_password):
        raise HTTPException(status_code=400, detail="Password lama Anda salah.")
    
    current_user.hashed_password = get_password_hash(data.new_password)
    db.commit()
    log_audit(db, request, "CHANGE_PASSWORD", "Password berhasil diubah", current_user)
    return {"message": "Password berhasil diperbarui."}

@app.post("/api/owner/admin-password")
async def reset_admin_password(
    data: AdminPasswordReset,
    request: Request,
    current_user: User = Depends(require_owner),
    db: Session = Depends(get_db)
):
    admin_user = db.query(User).filter(User.role == "admin").first()
    if not admin_user:
        raise HTTPException(status_code=404, detail="Akun admin tidak ditemukan.")
    
    admin_user.hashed_password = get_password_hash(data.new_password)
    db.commit()
    log_audit(db, request, "RESET_ADMIN_PASSWORD", f"Password admin '{admin_user.username}' diubah oleh Owner", current_user)
    return {"message": f"Password untuk akun admin '{admin_user.username}' berhasil diperbarui."}

# ============================================================
# DASHBOARD API
# ============================================================
@app.get("/api/dashboard")
async def get_dashboard(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # Total Saldo
    total_in = db.query(func.coalesce(func.sum(Transaction.amount), 0.0)).filter(Transaction.type == "masuk").scalar()
    total_out = db.query(func.coalesce(func.sum(Transaction.amount), 0.0)).filter(Transaction.type == "keluar").scalar()
    saldo = total_in - total_out

    # This Month
    today = date.today()
    cur_month_prefix = today.strftime("%Y-%m")
    month_in = db.query(func.coalesce(func.sum(Transaction.amount), 0.0)).filter(
        Transaction.type == "masuk",
        Transaction.date.startswith(cur_month_prefix)
    ).scalar()
    month_out = db.query(func.coalesce(func.sum(Transaction.amount), 0.0)).filter(
        Transaction.type == "keluar",
        Transaction.date.startswith(cur_month_prefix)
    ).scalar()
    net_month = month_in - month_out

    # Recent 5 transactions
    recent = db.query(Transaction).order_by(Transaction.date.desc(), Transaction.created_at.desc()).limit(5).all()

    # Trucks
    trucks = db.query(TruckSetting).order_by(TruckSetting.id.asc()).all()
    truck_count = len(trucks)
    first_truck = trucks[0] if trucks else None

    return {
        "saldo": saldo,
        "income_month": month_in,
        "expense_month": month_out,
        "net_month": net_month,
        "month_name": MN_INDO[today.month - 1],
        "year": today.year,
        "recent_transactions": [
            {
                "id": t.id,
                "date": t.date,
                "type": t.type,
                "category": t.category,
                "description": t.description,
                "penyewa": t.penyewa,
                "amount": t.amount,
                "created_by_name": t.created_by_name
            } for t in recent
        ],
        "truck_count": truck_count,
        "trucks": [
            {
                "id": t.id,
                "nopol": t.nopol or "",
                "jenis": t.jenis or "",
                "kapasitas": t.kapasitas or "",
                "tahun": t.tahun,
                "status": t.status or "",
                "cicilan": t.cicilan or 0.0
            } for t in trucks
        ],
        "truck": {
            "nopol": first_truck.nopol if first_truck else "–",
            "jenis": first_truck.jenis if first_truck else "Belum diisi",
            "kapasitas": first_truck.kapasitas if first_truck else "",
            "tahun": first_truck.tahun if first_truck else None,
            "status": first_truck.status if first_truck else "",
            "cicilan": first_truck.cicilan if first_truck else 0.0
        } if first_truck else None
    }

# ============================================================
# TRANSACTIONS ENDPOINTS
# ============================================================
@app.get("/api/transactions")
async def list_transactions(
    from_date: Optional[str] = None,
    to_date: Optional[str] = None,
    trx_type: Optional[str] = None,
    category: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    query = db.query(Transaction)
    if from_date:
        query = query.filter(Transaction.date >= from_date)
    if to_date:
        query = query.filter(Transaction.date <= to_date)
    if trx_type and trx_type in ["masuk", "keluar"]:
        query = query.filter(Transaction.type == trx_type)
    if category:
        query = query.filter(Transaction.category == category)

    transactions = query.order_by(Transaction.date.desc(), Transaction.created_at.desc()).all()
    
    total_in = sum(t.amount for t in transactions if t.type == "masuk")
    total_out = sum(t.amount for t in transactions if t.type == "keluar")

    return {
        "transactions": [
            {
                "id": t.id,
                "date": t.date,
                "type": t.type,
                "category": t.category,
                "description": t.description,
                "penyewa": t.penyewa,
                "amount": t.amount,
                "created_by_name": t.created_by_name,
                "created_at": t.created_at.isoformat()
            } for t in transactions
        ],
        "summary": {
            "total_masuk": total_in,
            "total_keluar": total_out,
            "saldo_periode": total_in - total_out
        }
    }

@app.post("/api/transactions", status_code=status.HTTP_201_CREATED)
async def create_transaction(
    payload: TransactionCreate,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    trx = Transaction(
        date=payload.date,
        type=payload.type,
        category=payload.category,
        description=payload.description or "",
        penyewa=payload.penyewa or "",
        amount=payload.amount,
        created_by_id=current_user.id,
        created_by_name=current_user.full_name
    )
    db.add(trx)
    db.commit()
    db.refresh(trx)

    log_audit(db, request, "CREATE_TRX", f"{trx.type.upper()}: Rp {trx.amount:,.0f} ({trx.category})", current_user)
    return {"message": "Transaksi berhasil disimpan", "id": trx.id}

@app.delete("/api/transactions/{trx_id}")
async def delete_transaction(
    trx_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    trx = db.query(Transaction).filter(Transaction.id == trx_id).first()
    if not trx:
        raise HTTPException(status_code=404, detail="Transaksi tidak ditemukan.")

    # Security check: Admin only can delete if Owner approves or Owner can delete anytime
    if current_user.role != "owner":
        # Check if created by the same admin on same day
        if trx.created_by_id != current_user.id or trx.date != date.today().isoformat():
            raise HTTPException(
                status_code=403,
                detail="Hanya Owner yang dapat menghapus transaksi dari periode sebelumnya."
            )

    info = f"{trx.date} | {trx.category} | Rp {trx.amount:,.0f}"
    db.delete(trx)
    db.commit()

    log_audit(db, request, "DELETE_TRX", info, current_user)
    return {"message": "Transaksi berhasil dihapus."}

# ============================================================
# REPORTS API (WEEKLY & MONTHLY)
# ============================================================
def week_range(year: int, week: int):
    # Calculate Monday and Sunday of the given ISO week
    d = date(year, 1, 4)
    start = d + timedelta(weeks=week - 1, days=-d.weekday())
    end = start + timedelta(days=6)
    return start.isoformat(), end.isoformat()

@app.get("/api/reports/weekly")
async def report_weekly(
    week: str,  # format: YYYY-Www
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    try:
        yr, ww = week.split("-W")
        start_date, end_date = week_range(int(yr), int(ww))
    except Exception:
        raise HTTPException(status_code=400, detail="Format minggu tidak valid (contoh: 2026-W41).")

    # Saldo awal (semua sebelum start_date)
    prev_in = db.query(func.coalesce(func.sum(Transaction.amount), 0.0)).filter(
        Transaction.type == "masuk", Transaction.date < start_date
    ).scalar()
    prev_out = db.query(func.coalesce(func.sum(Transaction.amount), 0.0)).filter(
        Transaction.type == "keluar", Transaction.date < start_date
    ).scalar()
    saldo_awal = prev_in - prev_out

    # Transaksi dalam minggu ini
    trx = db.query(Transaction).filter(
        Transaction.date >= start_date,
        Transaction.date <= end_date
    ).order_by(Transaction.date.asc()).all()

    masuk_list = [t for t in trx if t.type == "masuk"]
    keluar_list = [t for t in trx if t.type == "keluar"]
    total_masuk = sum(t.amount for t in masuk_list)
    total_keluar = sum(t.amount for t in keluar_list)
    saldo_akhir = saldo_awal + (total_masuk - total_keluar)

    return {
        "start_date": start_date,
        "end_date": end_date,
        "saldo_awal": saldo_awal,
        "total_masuk": total_masuk,
        "total_keluar": total_keluar,
        "kas_bersih": total_masuk - total_keluar,
        "saldo_akhir": saldo_akhir,
        "masuk_list": [
            {"date": t.date, "category": t.category, "penyewa": t.penyewa, "amount": t.amount} for t in masuk_list
        ],
        "keluar_list": [
            {"date": t.date, "category": t.category, "penyewa": t.penyewa, "amount": t.amount} for t in keluar_list
        ]
    }

@app.get("/api/reports/monthly")
async def report_monthly(
    month: str,  # format: YYYY-MM
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    try:
        yr, mo = map(int, month.split("-"))
        start_date = f"{month}-01"
        # calculate last day of month
        if mo == 12:
            last_day = 31
        else:
            last_day = (date(yr, mo + 1, 1) - timedelta(days=1)).day
        end_date = f"{month}-{last_day:02d}"
    except Exception:
        raise HTTPException(status_code=400, detail="Format bulan tidak valid (contoh: 2026-10).")

    # Saldo awal
    prev_in = db.query(func.coalesce(func.sum(Transaction.amount), 0.0)).filter(
        Transaction.type == "masuk", Transaction.date < start_date
    ).scalar()
    prev_out = db.query(func.coalesce(func.sum(Transaction.amount), 0.0)).filter(
        Transaction.type == "keluar", Transaction.date < start_date
    ).scalar()
    saldo_awal = prev_in - prev_out

    trx = db.query(Transaction).filter(
        Transaction.date >= start_date,
        Transaction.date <= end_date
    ).order_by(Transaction.date.asc()).all()

    total_masuk = sum(t.amount for t in trx if t.type == "masuk")
    total_keluar = sum(t.amount for t in trx if t.type == "keluar")
    net = total_masuk - total_keluar

    # Category breakdown
    cat_masuk = {}
    cat_keluar = {}
    daily_map = {f"{month}-{d:02d}": {"masuk": 0.0, "keluar": 0.0} for d in range(1, last_day + 1)}

    for t in trx:
        if t.type == "masuk":
            cat_masuk[t.category] = cat_masuk.get(t.category, 0.0) + t.amount
            if t.date in daily_map:
                daily_map[t.date]["masuk"] += t.amount
        else:
            cat_keluar[t.category] = cat_keluar.get(t.category, 0.0) + t.amount
            if t.date in daily_map:
                daily_map[t.date]["keluar"] += t.amount

    return {
        "month_str": month,
        "month_name": MN_INDO[mo - 1],
        "year": yr,
        "start_date": start_date,
        "end_date": end_date,
        "last_day": last_day,
        "saldo_awal": saldo_awal,
        "total_masuk": total_masuk,
        "total_keluar": total_keluar,
        "net": net,
        "saldo_akhir": saldo_awal + net,
        "categories_masuk": [{"category": k, "amount": v} for k, v in sorted(cat_masuk.items(), key=lambda x: x[1], reverse=True)],
        "categories_keluar": [{"category": k, "amount": v} for k, v in sorted(cat_keluar.items(), key=lambda x: x[1], reverse=True)],
        "daily": [
            {"date": d, "masuk": vals["masuk"], "keluar": vals["keluar"], "net": vals["masuk"] - vals["keluar"]}
            for d, vals in sorted(daily_map.items()) if vals["masuk"] > 0 or vals["keluar"] > 0
        ]
    }

# ============================================================
# TRUCK / FLEET SETTINGS API
# ============================================================
@app.get("/api/trucks", response_model=List[TruckSettingResponse])
async def list_trucks(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Mendapatkan daftar semua unit armada truk."""
    return db.query(TruckSetting).order_by(TruckSetting.id.asc()).all()

@app.post("/api/trucks", status_code=status.HTTP_201_CREATED, response_model=TruckSettingResponse)
async def create_truck(
    payload: TruckSettingCreate,
    request: Request,
    current_user: User = Depends(require_owner),
    db: Session = Depends(get_db)
):
    """Menambah unit armada baru (Owner Only)."""
    truck = TruckSetting(
        nopol=payload.nopol.upper(),
        jenis=payload.jenis,
        kapasitas=payload.kapasitas,
        tahun=payload.tahun,
        status=payload.status,
        cicilan=payload.cicilan or 0.0
    )
    db.add(truck)
    db.commit()
    db.refresh(truck)
    log_audit(db, request, "CREATE_TRUCK", f"Tambah unit nopol {truck.nopol}", current_user)
    return truck

@app.put("/api/trucks/{truck_id}", response_model=TruckSettingResponse)
async def update_truck(
    truck_id: int,
    payload: TruckSettingCreate,
    request: Request,
    current_user: User = Depends(require_owner),
    db: Session = Depends(get_db)
):
    """Memperbarui informasi unit armada (Owner Only)."""
    truck = db.query(TruckSetting).filter(TruckSetting.id == truck_id).first()
    if not truck:
        raise HTTPException(status_code=404, detail="Unit armada tidak ditemukan.")

    truck.nopol = payload.nopol.upper()
    truck.jenis = payload.jenis
    truck.kapasitas = payload.kapasitas
    truck.tahun = payload.tahun
    truck.status = payload.status
    truck.cicilan = payload.cicilan or 0.0
    db.commit()
    db.refresh(truck)
    log_audit(db, request, "UPDATE_TRUCK", f"Update unit nopol {truck.nopol}", current_user)
    return truck

@app.delete("/api/trucks/{truck_id}")
async def delete_truck(
    truck_id: int,
    request: Request,
    current_user: User = Depends(require_owner),
    db: Session = Depends(get_db)
):
    """Menghapus / mengurangi unit armada dari daftar (Owner Only)."""
    truck = db.query(TruckSetting).filter(TruckSetting.id == truck_id).first()
    if not truck:
        raise HTTPException(status_code=404, detail="Unit armada tidak ditemukan.")

    nopol = truck.nopol
    db.delete(truck)
    db.commit()
    log_audit(db, request, "DELETE_TRUCK", f"Hapus unit nopol {nopol}", current_user)
    return {"message": f"Unit armada {nopol} berhasil dihapus."}

@app.get("/api/truck")
async def get_truck_setting(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Endpoint kompatibilitas untuk unit armada pertama."""
    truck = db.query(TruckSetting).first()
    if not truck:
        return {}
    return {
        "id": truck.id,
        "nopol": truck.nopol,
        "jenis": truck.jenis,
        "kapasitas": truck.kapasitas,
        "tahun": truck.tahun,
        "status": truck.status,
        "cicilan": truck.cicilan
    }

@app.post("/api/truck")
async def save_truck_setting(
    payload: TruckSettingSchema,
    request: Request,
    current_user: User = Depends(require_owner),
    db: Session = Depends(get_db)
):
    """Endpoint kompatibilitas untuk update unit armada pertama."""
    truck = db.query(TruckSetting).first()
    if not truck:
        truck = TruckSetting()
        db.add(truck)

    truck.nopol = payload.nopol.upper() if payload.nopol else ""
    truck.jenis = payload.jenis
    truck.kapasitas = payload.kapasitas
    truck.tahun = payload.tahun
    truck.status = payload.status
    truck.cicilan = payload.cicilan or 0.0
    db.commit()

    log_audit(db, request, "UPDATE_TRUCK", f"Nopol: {truck.nopol}", current_user)
    return {"message": "Data armada berhasil disimpan."}

# ============================================================
# BACKUP & AUDIT EXPORT (OWNER ONLY)
# ============================================================
@app.get("/api/backup/export")
async def export_backup(
    current_user: User = Depends(require_owner),
    db: Session = Depends(get_db)
):
    all_trx = db.query(Transaction).all()
    trucks = db.query(TruckSetting).order_by(TruckSetting.id.asc()).all()
    first_truck = trucks[0] if trucks else None

    return {
        "company": "PT KYNAN RAHARJA PRATAMA",
        "exported_at": datetime.utcnow().isoformat(),
        "exported_by": current_user.username,
        "trucks": [
            {
                "nopol": t.nopol or "",
                "jenis": t.jenis or "",
                "kapasitas": t.kapasitas or "",
                "tahun": t.tahun,
                "status": t.status or "",
                "cicilan": t.cicilan or 0.0
            } for t in trucks
        ],
        "truck": {
            "nopol": first_truck.nopol if first_truck else "",
            "jenis": first_truck.jenis if first_truck else "",
            "kapasitas": first_truck.kapasitas if first_truck else "",
            "tahun": first_truck.tahun if first_truck else None,
            "status": first_truck.status if first_truck else "",
            "cicilan": first_truck.cicilan if first_truck else 0.0
        } if first_truck else {},
        "transactions": [
            {
                "id": t.id,
                "date": t.date,
                "type": t.type,
                "category": t.category,
                "description": t.description,
                "penyewa": t.penyewa,
                "amount": t.amount,
                "created_by_name": t.created_by_name,
                "created_at": t.created_at.isoformat()
            } for t in all_trx
        ]
    }

@app.post("/api/backup/import")
async def import_backup(
    payload: dict,
    request: Request,
    current_user: User = Depends(require_owner),
    db: Session = Depends(get_db)
):
    raw_trx = payload.get("transactions", [])
    raw_trucks = payload.get("trucks", [])
    raw_truck = payload.get("truck", {})

    imported_count = 0
    for t_data in raw_trx:
        date_val = str(t_data.get("date", "")).strip()
        type_val = str(t_data.get("type", "masuk")).strip()
        cat_val = str(t_data.get("category", "Lain-lain")).strip()
        try:
            amt_val = float(t_data.get("amount", 0.0))
        except (ValueError, TypeError):
            amt_val = 0.0

        if not date_val or amt_val <= 0:
            continue

        trx = Transaction(
            date=date_val,
            type=type_val if type_val in ["masuk", "keluar"] else "masuk",
            category=cat_val,
            description=str(t_data.get("description", "")).strip(),
            penyewa=str(t_data.get("penyewa", "")).strip(),
            amount=amt_val,
            created_by_id=current_user.id,
            created_by_name=current_user.full_name
        )
        db.add(trx)
        imported_count += 1

    if raw_trucks and isinstance(raw_trucks, list):
        for rt in raw_trucks:
            if not isinstance(rt, dict) or not rt.get("nopol"):
                continue
            nopol_str = str(rt["nopol"]).strip().upper()
            existing = db.query(TruckSetting).filter(TruckSetting.nopol == nopol_str).first()
            if not existing:
                existing = TruckSetting()
                db.add(existing)
            existing.nopol = nopol_str
            existing.jenis = str(rt.get("jenis", "")).strip()
            existing.kapasitas = str(rt.get("kapasitas", "")).strip()
            if rt.get("tahun"):
                try:
                    existing.tahun = int(rt["tahun"])
                except (ValueError, TypeError):
                    pass
            existing.status = str(rt.get("status", "")).strip()
            if "cicilan" in rt:
                try:
                    existing.cicilan = float(rt["cicilan"])
                except (ValueError, TypeError):
                    pass
    elif raw_truck and isinstance(raw_truck, dict):
        truck = db.query(TruckSetting).first()
        if not truck:
            truck = TruckSetting()
            db.add(truck)
        if raw_truck.get("nopol"):
            truck.nopol = str(raw_truck["nopol"]).strip().upper()
        if raw_truck.get("jenis"):
            truck.jenis = str(raw_truck["jenis"]).strip()
        if raw_truck.get("kapasitas"):
            truck.kapasitas = str(raw_truck["kapasitas"]).strip()
        if raw_truck.get("tahun"):
            try:
                truck.tahun = int(raw_truck["tahun"])
            except (ValueError, TypeError):
                pass
        if raw_truck.get("status"):
            truck.status = str(raw_truck["status"]).strip()
        if "cicilan" in raw_truck:
            try:
                truck.cicilan = float(raw_truck["cicilan"])
            except (ValueError, TypeError):
                pass

    db.commit()
    log_audit(db, request, "IMPORT_BACKUP", f"Dipulihkan {imported_count} transaksi", current_user)
    return {"message": f"Berhasil memulihkan {imported_count} data transaksi."}

@app.delete("/api/backup/clear")
async def clear_all_transactions(
    request: Request,
    current_user: User = Depends(require_owner),
    db: Session = Depends(get_db)
):
    count = db.query(Transaction).delete()
    db.commit()
    log_audit(db, request, "CLEAR_ALL_DATA", f"Dihapus {count} transaksi", current_user)
    return {"message": f"Semua data transaksi ({count} item) telah dihapus."}


# ============================================================
# STATIC FILES & ROOT
# ============================================================
static_dir = os.path.join(os.path.dirname(__file__), "static")
if not os.path.exists(static_dir):
    os.makedirs(static_dir, exist_ok=True)

app.mount("/static", StaticFiles(directory=static_dir), name="static")

@app.get("/")
async def serve_index():
    index_path = os.path.join(static_dir, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return {"message": "PT KYNAN RAHARJA PRATAMA Cash Flow API is Running."}
