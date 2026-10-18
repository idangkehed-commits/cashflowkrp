import os
from dotenv import load_dotenv

load_dotenv()


class Settings:
    ENVIRONMENT = os.getenv('ENVIRONMENT', 'development')
    DEBUG = ENVIRONMENT != 'production'
    RAW_DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:///./cashflow.db')
    PUBLIC_ORIGIN = os.getenv('PUBLIC_ORIGIN', os.getenv('RENDER_EXTERNAL_URL', 'https://cashflowkrp.onrender.com')).rstrip('/')
    SESSION_MINUTES = int(os.getenv('SESSION_MINUTES', '480'))
    COOKIE_NAME = '__Host-krp_session' if not DEBUG else 'krp_session'
    DEFAULT_OWNER_USERNAME = os.getenv('DEFAULT_OWNER_USER', 'owner')
    DEFAULT_ADMIN_USERNAME = os.getenv('DEFAULT_ADMIN_USER', 'admin')
    DEFAULT_OWNER_NAME = 'Owner PT KYNAN RAHARJA PRATAMA'
    DEFAULT_ADMIN_NAME = 'Admin Operasional KRP'
    OWNER_EMAIL = os.getenv('OWNER_EMAIL', '').strip().lower()
    ADMIN_EMAIL = os.getenv('ADMIN_EMAIL', '').strip().lower()
    OWNER_INITIAL_PASSWORD = os.getenv('OWNER_INITIAL_PASSWORD', '')
    ADMIN_INITIAL_PASSWORD = os.getenv('ADMIN_INITIAL_PASSWORD', '')

    @property
    def DATABASE_URL(self):
        return self.RAW_DATABASE_URL.replace('postgres://', 'postgresql://', 1)


settings = Settings()
