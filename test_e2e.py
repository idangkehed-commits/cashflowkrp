from datetime import date
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_full_flow():
    # 1. Test Static Root
    r_root = client.get("/")
    assert r_root.status_code == 200, f"Root status {r_root.status_code}"
    assert "Cash Flow – PT KYNAN RAHARJA PRATAMA" in r_root.text
    assert "authOverlay" in r_root.text
    assert "API CLIENT & AUTHENTICATION" in r_root.text
    print("[OK] Root and static index.html verified successfully")

    # 2. Test Login
    r_login_bad = client.post("/api/auth/login", json={"username": "admin", "password": "WrongPassword!"})
    assert r_login_bad.status_code == 401, f"Expected 401 got {r_login_bad.status_code}"

    r_login_admin = client.post("/api/auth/login", json={"username": "admin", "password": "AdminKRP2026!"})
    assert r_login_admin.status_code == 200
    admin_token = r_login_admin.json()["access_token"]
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    r_login_owner = client.post("/api/auth/login", json={"username": "owner", "password": "OwnerKRP2026!"})
    assert r_login_owner.status_code == 200
    owner_token = r_login_owner.json()["access_token"]
    owner_headers = {"Authorization": f"Bearer {owner_token}"}
    print("[OK] Authentication and JWT issuing verified successfully")

    # 3. Test Transaction Creation
    today_str = date.today().isoformat()
    r_create_in = client.post("/api/transactions", headers=admin_headers, json={
        "date": today_str,
        "type": "masuk",
        "category": "Pendapatan Sewa Harian",
        "description": "Sewa unit truk 1 hari rute Karawang",
        "penyewa": "PT Maju Bersama",
        "amount": 2500000.0
    })
    assert r_create_in.status_code == 201
    trx_id = r_create_in.json()["id"]

    r_create_out = client.post("/api/transactions", headers=owner_headers, json={
        "date": today_str,
        "type": "keluar",
        "category": "Bahan Bakar (BBM)",
        "description": "Isi solar penuh sebelum jalan",
        "penyewa": "",
        "amount": 450000.0
    })
    assert r_create_out.status_code == 201
    print("[OK] Transaction creation (Income & Expense) verified successfully")

    # 4. Test Dashboard
    r_dash = client.get("/api/dashboard", headers=admin_headers)
    assert r_dash.status_code == 200
    dash_data = r_dash.json()
    assert dash_data["saldo"] == 2050000.0, f"Expected saldo 2050000, got {dash_data['saldo']}"
    assert dash_data["income_month"] == 2500000.0
    assert dash_data["expense_month"] == 450000.0
    print("[OK] Dashboard calculation verified successfully")

    # 5. Test Reports
    cur_month = today_str[:7]
    r_monthly = client.get(f"/api/reports/monthly?month={cur_month}", headers=admin_headers)
    assert r_monthly.status_code == 200
    monthly_data = r_monthly.json()
    assert monthly_data["total_masuk"] == 2500000.0
    assert monthly_data["total_keluar"] == 450000.0
    assert monthly_data["net"] == 2050000.0
    print("[OK] Monthly report calculation verified successfully")

    # 6. Test RBAC (Owner vs Admin)
    r_admin_backup = client.get("/api/backup/export", headers=admin_headers)
    assert r_admin_backup.status_code == 403, f"Expected 403 for admin backup, got {r_admin_backup.status_code}"

    r_owner_backup = client.get("/api/backup/export", headers=owner_headers)
    assert r_owner_backup.status_code == 200, f"Expected 200 for owner backup, got {r_owner_backup.status_code}"
    assert len(r_owner_backup.json()["transactions"]) >= 2
    print("[OK] Role-based access control (RBAC) verified successfully")

    # 7. Test Delete
    r_del = client.delete(f"/api/transactions/{trx_id}", headers=admin_headers)
    assert r_del.status_code == 200
    print("[OK] Transaction deletion verified successfully")

    # 8. Test Admin Password Change by Owner
    r_adm_change_forbidden = client.post("/api/owner/admin-password", headers=admin_headers, json={"new_password": "NewAdminPass123!"})
    assert r_adm_change_forbidden.status_code == 403, f"Admin shouldn't be able to call owner password endpoint: {r_adm_change_forbidden.status_code}"

    r_adm_change_ok = client.post("/api/owner/admin-password", headers=owner_headers, json={"new_password": "NewAdminPass123!"})
    assert r_adm_change_ok.status_code == 200
    print("[OK] Owner changed Admin password successfully")

    # Verify admin can login with new password
    r_login_new_adm = client.post("/api/auth/login", json={"username": "admin", "password": "NewAdminPass123!"})
    assert r_login_new_adm.status_code == 200
    new_admin_token = r_login_new_adm.json()["access_token"]
    new_admin_headers = {"Authorization": f"Bearer {new_admin_token}"}
    print("[OK] Admin verified login with newly set password")

    # Restore admin password for default compatibility
    client.post("/api/owner/admin-password", headers=owner_headers, json={"new_password": "AdminKRP2026!"})

    # 9. Test Fleet Management (Kelola Unit Armada - Tambah & Kurangi Unit)
    r_trucks = client.get("/api/trucks", headers=admin_headers)
    assert r_trucks.status_code == 200
    initial_truck_count = len(r_trucks.json())

    # Admin cannot add truck
    r_truck_admin_add = client.post("/api/trucks", headers=new_admin_headers, json={
        "nopol": "D 1234 KRP",
        "jenis": "Truk Box",
        "kapasitas": "5 Ton",
        "tahun": 2024,
        "status": "Milik Sendiri (Lunas)",
        "cicilan": 0.0
    })
    assert r_truck_admin_add.status_code == 403

    # Owner adds truck (Tambah unit)
    r_truck_add = client.post("/api/trucks", headers=owner_headers, json={
        "nopol": "D 1234 KRP",
        "jenis": "Truk Box",
        "kapasitas": "5 Ton",
        "tahun": 2024,
        "status": "Milik Sendiri (Lunas)",
        "cicilan": 0.0
    })
    assert r_truck_add.status_code == 201
    new_truck_id = r_truck_add.json()["id"]
    assert r_truck_add.json()["nopol"] == "D 1234 KRP"
    print("[OK] Owner successfully added new truck unit")

    # Verify list count increased
    r_trucks_after = client.get("/api/trucks", headers=owner_headers)
    assert len(r_trucks_after.json()) == initial_truck_count + 1

    # Owner updates truck
    r_truck_upd = client.put(f"/api/trucks/{new_truck_id}", headers=owner_headers, json={
        "nopol": "D 1234 KRP",
        "jenis": "Truk Box Pendingin",
        "kapasitas": "6 Ton",
        "tahun": 2024,
        "status": "Milik Sendiri (Lunas)",
        "cicilan": 0.0
    })
    assert r_truck_upd.status_code == 200
    assert r_truck_upd.json()["jenis"] == "Truk Box Pendingin"

    # Owner deletes truck (Kurangi unit)
    r_truck_del = client.delete(f"/api/trucks/{new_truck_id}", headers=owner_headers)
    assert r_truck_del.status_code == 200
    print("[OK] Owner successfully deleted (reduced) truck unit")

    # Verify list count back to initial
    r_trucks_final = client.get("/api/trucks", headers=owner_headers)
    assert len(r_trucks_final.json()) == initial_truck_count

    # 10. Clean up test database
    r_clear = client.delete("/api/backup/clear", headers=owner_headers)
    assert r_clear.status_code == 200
    print("[OK] Database cleaned up to pristine state")

    print("\nALL VERIFICATION TESTS PASSED PERFECTLY!")

if __name__ == "__main__":
    test_full_flow()
