from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import IntegrityError

from fastapi import HTTPException, status

from src.apps.db.models.user_model import User
from src.apps.db.models.password_reset_otp_model import PasswordResetOTP
from src.apps.db.models.refresh_token_model import RefreshToken
from src.apps.db.schemas.auth_schema import UserRegister

from datetime import datetime, timedelta, timezone

from src.apps.core.security import (
    verify_password,
    hash_password,
    create_access_token,
    create_refresh_token,
    decode_token,
    generate_otp,
    hash_otp,
    verify_otp
)

from src.apps.core.config import settings

from src.apps.services.email_service import (
    send_password_reset_otp
)


async def register_user(
    user_data: UserRegister,
    db: AsyncSession
) -> User:

    # 1. Normalize email
    normalized_email = user_data.email.strip().lower()

    # 2. Check whether email already exists
    query = select(User).where(
        User.email == normalized_email
    )

    result = await db.execute(query)
    existing_user = result.scalar_one_or_none()

    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email already exists."
        )

    # 3. Hash password
    hashed_password = hash_password(user_data.password)

    # 4. Create user object
    new_user = User(
        full_name=user_data.full_name.strip(),
        email=normalized_email,
        password_hash=hashed_password
    )

    try:
        # 5. Save user
        db.add(new_user)

        await db.commit()

        # 6. Refresh database-generated fields
        await db.refresh(new_user)

        return new_user

    except IntegrityError:
        await db.rollback()

        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email already exists."
        )

    except Exception:
        await db.rollback()
        raise


# =====================================
# LOGIN SERVICE
# =====================================

async def login_user(
    db: AsyncSession,
    email: str,
    password: str
):

    result = await db.execute(
        select(User).where(
            User.email == email.lower()
        )
    )

    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password"
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is inactive"
        )

    if user.locked_until and user.locked_until > datetime.now(timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is locked due to multiple failed login attempts"
        )

    if not verify_password(
        password,
        user.password_hash
    ):
        user.failed_login_attempts += 1

        if user.failed_login_attempts >= 5:
            user.locked_until = datetime.now(
                timezone.utc
            ) + timedelta(minutes=30)

        await db.commit()

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password"
        )

    # Reset failed attempts on successful login
    user.failed_login_attempts = 0
    user.locked_until = None

    access_token = create_access_token(
        str(user.id)
    )

    refresh_token_jwt = create_refresh_token(
        str(user.id)
    )

    # Decode to get JTI for storage
    refresh_payload = decode_token(refresh_token_jwt)
    refresh_jti = refresh_payload.get("jti")
    refresh_expires = datetime.fromtimestamp(
        refresh_payload.get("exp", 0),
        tz=timezone.utc,
    )

    # Revoke all previous unused refresh tokens for this user
    await db.execute(
        update(RefreshToken)
        .where(
            RefreshToken.user_id == user.id,
            RefreshToken.is_revoked == False
        )
        .values(is_revoked=True, revoked_at=datetime.now(timezone.utc))
    )

    # Store new refresh token
    refresh_token_record = RefreshToken(
        user_id=user.id,
        jti=refresh_jti,
        expires_at=refresh_expires,
        is_revoked=False,
    )
    db.add(refresh_token_record)

    await db.commit()

    return {
        "access_token": access_token,
        "refresh_token": refresh_token_jwt,
        "token_type": "bearer",
        "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
    }


# =====================================
# LOGOUT SERVICE
# =====================================

async def logout_user(
    db: AsyncSession,
    refresh_token: str
):
    try:
        payload = decode_token(refresh_token)

        if payload.get("type") != "refresh":
            raise ValueError("Invalid token type")

        jti = payload.get("jti")
        if not jti:
            raise ValueError("Missing JTI")

    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token"
        )

    result = await db.execute(
        select(RefreshToken).where(RefreshToken.jti == jti)
    )
    token_record = result.scalar_one_or_none()

    if token_record:
        token_record.is_revoked = True
        token_record.revoked_at = datetime.now(timezone.utc)
        await db.commit()

    return {"message": "Logged out successfully"}


# =====================================
# REFRESH ACCESS TOKEN SERVICE
# =====================================

async def refresh_access_token(
    db: AsyncSession,
    refresh_token: str
):

    try:
        payload = decode_token(refresh_token)

        if payload.get("type") != "refresh":
            raise ValueError("Invalid token type")

        user_id = payload.get("sub")
        jti = payload.get("jti")

        if not user_id:
            raise ValueError("Missing user ID")
        if not jti:
            raise ValueError("Missing JTI")

    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token"
        )

    # Check refresh token in database
    result = await db.execute(
        select(RefreshToken).where(
            RefreshToken.jti == jti,
            RefreshToken.user_id == user_id,
        )
    )
    token_record = result.scalar_one_or_none()

    if not token_record:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found or revoked"
        )

    if token_record.is_revoked:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token has been revoked"
        )

    now = datetime.now(timezone.utc)
    if token_record.expires_at <= now:
        token_record.is_revoked = True
        token_record.revoked_at = now
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token has expired"
        )

    user_result = await db.execute(
        select(User).where(User.id == user_id)
    )
    user = user_result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found"
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is inactive"
        )

    # Rotate: revoke old token, issue new
    token_record.is_revoked = True
    token_record.revoked_at = now

    new_access_token = create_access_token(str(user.id))
    new_refresh_token_jwt = create_refresh_token(str(user.id))

    new_payload = decode_token(new_refresh_token_jwt)
    new_jti = new_payload.get("jti")
    new_expires = datetime.fromtimestamp(
        new_payload.get("exp", 0),
        tz=timezone.utc,
    )

    new_token_record = RefreshToken(
        user_id=user.id,
        jti=new_jti,
        expires_at=new_expires,
        is_revoked=False,
    )
    db.add(new_token_record)

    await db.commit()

    return {
        "access_token": new_access_token,
        "refresh_token": new_refresh_token_jwt,
        "token_type": "bearer",
        "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
    }


async def get_user_by_id(
    db: AsyncSession,
    user_id: str
) -> User | None:
    result = await db.execute(
        select(User).where(User.id == user_id)
    )
    return result.scalar_one_or_none()


# =====================================
# FORGOT PASSWORD SERVICE
# =====================================

async def forgot_password(
    db: AsyncSession,
    email: str
):

    result = await db.execute(
        select(User).where(
            User.email == email.lower()
        )
    )

    user = result.scalar_one_or_none()

    # Return the same response for existing
    # and non-existing email addresses.

    if not user:
        return {
            "message": (
                "If an account exists with this email, "
                "a password reset OTP will be sent."
            )
        }

    otp = generate_otp()

    otp_hash = hash_otp(otp)

    expires_at = datetime.now(
        timezone.utc
    ) + timedelta(
        minutes=settings.OTP_EXPIRE_MINUTES
    )

    # Invalidate previous unused OTPs.

    await db.execute(
        update(PasswordResetOTP)
        .where(
            PasswordResetOTP.user_id == user.id,
            PasswordResetOTP.is_used == False
        )
        .values(is_used=True)
    )

    otp_record = PasswordResetOTP(
        user_id=user.id,
        otp_hash=otp_hash,
        expires_at=expires_at,
        attempts=0,
        is_used=False
    )

    db.add(otp_record)

    await db.commit()

    try:

        await send_password_reset_otp(
            user.email,
            otp
        )

    except Exception as e:

        import logging
        logger = logging.getLogger(__name__)
        logger.error("Failed to send password reset email: %s", str(e))

        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Unable to send password reset email. Please try again."
        )

    return {
        "message": (
            "If an account exists with this email, "
            "a password reset OTP will be sent."
        )
    }


# =====================================
# RESET PASSWORD SERVICE
# =====================================

async def reset_password(
    db: AsyncSession,
    email: str,
    otp: str,
    new_password: str
):

    result = await db.execute(
        select(User).where(
            User.email == email.lower()
        )
    )

    user = result.scalar_one_or_none()

    if not user:

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired OTP"
        )

    result = await db.execute(
        select(PasswordResetOTP)
        .where(
            PasswordResetOTP.user_id == user.id,
            PasswordResetOTP.is_used == False
        )
        .order_by(
            PasswordResetOTP.created_at.desc()
        )
        .limit(1)
        .with_for_update()
    )

    otp_record = result.scalar_one_or_none()

    if not otp_record:

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired OTP"
        )

    now = datetime.now(timezone.utc)

    if otp_record.expires_at <= now:

        otp_record.is_used = True

        await db.commit()

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="OTP has expired"
        )

    if otp_record.attempts >= settings.OTP_MAX_ATTEMPTS:

        otp_record.is_used = True

        await db.commit()

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Maximum OTP attempts exceeded"
        )

    if not verify_otp(
        otp,
        otp_record.otp_hash
    ):

        otp_record.attempts += 1

        if otp_record.attempts >= settings.OTP_MAX_ATTEMPTS:
            otp_record.is_used = True

        await db.commit()

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid OTP"
        )

    # OTP verified successfully.

    user.password_hash = hash_password(
        new_password
    )

    otp_record.is_used = True

    # Invalidate any other outstanding OTPs.

    await db.execute(
        update(PasswordResetOTP)
        .where(
            PasswordResetOTP.user_id == user.id,
            PasswordResetOTP.is_used == False
        )
        .values(is_used=True)
    )

    await db.commit()

    return {
        "message": "Password reset successfully"
    }
