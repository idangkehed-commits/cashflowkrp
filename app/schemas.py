from datetime import datetime
from typing import Optional, List, Literal
from pydantic import BaseModel, Field, field_validator
import html

class UserLogin(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=6, max_length=100)

class UserResponse(BaseModel):
    id: int
    username: str
    full_name: str
    role: str

    class Config:
        from_attributes = True

class UserChangePassword(BaseModel):
    old_password: str
    new_password: str = Field(..., min_length=6, max_length=100)

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse

class TransactionCreate(BaseModel):
    date: str = Field(..., pattern=r"^\d{4}-\d{2}-\d{2}$", description="Format YYYY-MM-DD")
    type: Literal["masuk", "keluar"]
    category: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = Field(default="", max_length=255)
    penyewa: Optional[str] = Field(default="", max_length=150)
    amount: float = Field(..., gt=0, description="Nominal harus lebih dari Rp 0")

    @field_validator("category", "description", "penyewa")
    @classmethod
    def sanitize_strings(cls, v: Optional[str]) -> str:
        if v is None:
            return ""
        # Escape HTML to prevent Stored XSS
        return html.escape(v.strip())

class TransactionResponse(BaseModel):
    id: str
    date: str
    type: str
    category: str
    description: Optional[str] = ""
    penyewa: Optional[str] = ""
    amount: float
    created_by_name: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True

class AdminPasswordReset(BaseModel):
    new_password: str = Field(..., min_length=6, max_length=100)

class TruckSettingSchema(BaseModel):
    nopol: Optional[str] = Field(default="", max_length=30)
    jenis: Optional[str] = Field(default="", max_length=50)
    kapasitas: Optional[str] = Field(default="", max_length=50)
    tahun: Optional[int] = Field(default=None)
    status: Optional[str] = Field(default="", max_length=50)
    cicilan: Optional[float] = Field(default=0.0)

    @field_validator("nopol", "jenis", "kapasitas", "status")
    @classmethod
    def sanitize(cls, v: Optional[str]) -> str:
        if v is None:
            return ""
        return html.escape(v.strip())

    class Config:
        from_attributes = True

class TruckSettingCreate(BaseModel):
    nopol: str = Field(..., min_length=3, max_length=30)
    jenis: Optional[str] = Field(default="", max_length=50)
    kapasitas: Optional[str] = Field(default="", max_length=50)
    tahun: Optional[int] = Field(default=None)
    status: Optional[str] = Field(default="", max_length=50)
    cicilan: Optional[float] = Field(default=0.0)

    @field_validator("nopol", "jenis", "kapasitas", "status")
    @classmethod
    def sanitize(cls, v: Optional[str]) -> str:
        if v is None:
            return ""
        return html.escape(v.strip())

class TruckSettingResponse(BaseModel):
    id: int
    nopol: Optional[str] = ""
    jenis: Optional[str] = ""
    kapasitas: Optional[str] = ""
    tahun: Optional[int] = None
    status: Optional[str] = ""
    cicilan: Optional[float] = 0.0

    class Config:
        from_attributes = True

class DashboardSummary(BaseModel):
    saldo: float
    income_month: float
    expense_month: float
    net_month: float
    month_name: str
    recent_transactions: List[TransactionResponse]
    truck: Optional[TruckSettingSchema] = None
    truck_count: Optional[int] = 0
    trucks: Optional[List[TruckSettingResponse]] = []
