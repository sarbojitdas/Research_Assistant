from fastapi import APIRouter, Depends, status, Request
from sqlalchemy.ext.asyncio import AsyncSession

from src.apps.core.database import get_db
from src.apps.core.rate_limit import auth_rate_limit

from src.apps.db.schemas.auth_schema import (
    UserRegister,
    UserResponse,
    LoginRequest,
    TokenResponse,
    RefreshTokenRequest,
    ForgotPasswordRequest,
    ResetPasswordRequest,
)

from src.apps.services.auth_service import (
    register_user,
    login_user,
    refresh_access_token,
    forgot_password,
    reset_password,
    logout_user,
    get_user_by_id,
)

from src.apps.dependencies.auth import CurrentUser

router = APIRouter(
    prefix="/auth",
    tags=["Authentication"]
)


def _client_key(request: Request) -> str:
    return request.client.host if request.client else "unknown"


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED
)
async def register(
    request: Request,
    user_data: UserRegister,
    db: AsyncSession = Depends(get_db)
):
    auth_rate_limit(f"register:{_client_key(request)}")

    """
    Register a new user.

    - Validates user input.
    - Checks duplicate email.
    - Hashes password using Argon2.
    - Saves user in Supabase PostgreSQL.
    - Returns registered user information.
    """

    user = await register_user(
        user_data=user_data,
        db=db
    )

    return user


# =====================================
# LOGIN API
# =====================================

@router.post(
    "/login",
    response_model=TokenResponse
)
async def login(
    request: Request,
    login_request: LoginRequest,
    db: AsyncSession = Depends(get_db)
):
    auth_rate_limit(f"login:{_client_key(request)}")

    return await login_user(
        db,
        login_request.email,
        login_request.password
    )


# =====================================
# LOGOUT API
# =====================================

@router.post("/logout")
async def logout(
    request: Request,
    request_body: RefreshTokenRequest,
    db: AsyncSession = Depends(get_db)
):
    auth_rate_limit(f"logout:{_client_key(request)}")

    return await logout_user(
        db,
        request_body.refresh_token
    )


# =====================================
# REFRESH ACCESS TOKEN API
# =====================================

@router.post("/refresh")
async def refresh_token(
    request: Request,
    request_body: RefreshTokenRequest,
    db: AsyncSession = Depends(get_db)
):
    auth_rate_limit(f"refresh:{_client_key(request)}")

    return await refresh_access_token(
        db,
        request_body.refresh_token
    )


# =====================================
# CURRENT USER API
# =====================================

@router.get("/me", response_model=UserResponse)
async def get_current_user_profile(
    current_user: CurrentUser
):
    return current_user


# =====================================
# FORGOT PASSWORD API
# =====================================

@router.post("/forgot-password")
async def forgot_password_api(
    request: Request,
    request_body: ForgotPasswordRequest,
    db: AsyncSession = Depends(get_db)
):
    auth_rate_limit(f"forgot-password:{_client_key(request)}")

    return await forgot_password(
        db,
        request_body.email
    )


# =====================================
# RESET PASSWORD API
# =====================================

@router.post("/reset-password")
async def reset_password_api(
    request: Request,
    request_body: ResetPasswordRequest,
    db: AsyncSession = Depends(get_db)
):
    auth_rate_limit(f"reset-password:{_client_key(request)}")

    return await reset_password(
        db,
        request_body.email,
        request_body.otp,
        request_body.new_password
    )
