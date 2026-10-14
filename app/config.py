import os

class Settings:
    # Security: Secret Key for JWT Signing
    SECRET_KEY: str = os.getenv("SECRET_KEY", "krp-super-secure-production-secret-key-change-in-env-2026")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "480"))  # 8 jam
    
    # Environment
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")
    DEBUG: bool = ENVIRONMENT != "production"

    # Database: Render PostgreSQL or Local SQLite
    RAW_DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./cashflow.db")
    
    @property
    def DATABASE_URL(self) -> str:
        url = self.RAW_DATABASE_URL
        # Render uses postgres:// which SQLAlchemy 1.4+ / 2.0 requires postgresql://
        if url.startswith("postgres://"):
            url = url.replace("postgres://", "postgresql://", 1)
        return url

    # Default Credentials (hanya di-seed jika database masih kosong)
    DEFAULT_OWNER_USERNAME: str = os.getenv("DEFAULT_OWNER_USER", "owner")
    DEFAULT_OWNER_PASSWORD: str = os.getenv("DEFAULT_OWNER_PASS", "OwnerKRP2026!")
    DEFAULT_OWNER_NAME: str = "Owner PT KYNAN RAHARJA PRATAMA"

    DEFAULT_ADMIN_USERNAME: str = os.getenv("DEFAULT_ADMIN_USER", "admin")
    DEFAULT_ADMIN_PASSWORD: str = os.getenv("DEFAULT_ADMIN_PASS", "AdminKRP2026!")
    DEFAULT_ADMIN_NAME: str = "Admin Operasional KRP"

    # Rate limiting untuk mencegah Brute-Force Login (5 percobaan dalam 5 menit, lockout 15 menit)
    LOGIN_MAX_ATTEMPTS: int = 5
    LOGIN_LOCKOUT_MINUTES: int = 15

settings = Settings()
