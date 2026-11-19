from pydantic import BaseModel, EmailStr, Field, model_validator
from uuid import UUID
from datetime import datetime


class UserRegister(BaseModel):
    full_name: str = Field(min_length=2, max_length=150)
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    confirm_password: str = Field(min_length=8, max_length=128)

    @model_validator(mode="after")
    def validate_passwords(self):
        if self.password != self.confirm_password:
            raise ValueError("Password and confirm password do not match.")
        return self


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class UserResponse(BaseModel):
    id: UUID
    full_name: str
    email: EmailStr
    created_at: datetime

    model_config = {
        "from_attributes": True
    }


class LoginRequest(BaseModel):

    email: EmailStr

    password: str = Field(
        min_length=8
    )


# -----------------------------
# Token Response
# -----------------------------

class TokenResponse(BaseModel):

    access_token: str

    refresh_token: str

    token_type: str = "bearer"

    expires_in: int


# -----------------------------
# Refresh Token
# -----------------------------

class RefreshTokenRequest(BaseModel):

    refresh_token: str


# -----------------------------
# Forgot Password
# -----------------------------

class ForgotPasswordRequest(BaseModel):

    email: EmailStr


# -----------------------------
# Reset Password
# -----------------------------

class ResetPasswordRequest(BaseModel):

    email: EmailStr

    otp: str = Field(
        min_length=6,
        max_length=6,
        pattern=r"^\d{6}$"
    )

    new_password: str = Field(
        min_length=8
    )

    confirm_password: str = Field(
        min_length=8
    )

    @model_validator(mode="after")
    def validate_passwords(self):

        if self.new_password != self.confirm_password:

            raise ValueError(
                "Passwords do not match"
            )

        return self