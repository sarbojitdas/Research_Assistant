import pytest
from httpx import AsyncClient

from tests.conftest import client, db_session, test_user, mock_email  # noqa: F401


class TestRegistration:
    async def test_successful_registration(
        self, client: AsyncClient, mock_email: None
    ) -> None:
        response = await client.post(
            "/api/v1/auth/register",
            json={
                "full_name": "John Doe",
                "email": "john@example.com",
                "password": "SecurePass123",
                "confirm_password": "SecurePass123",
            },
        )
        assert response.status_code == 201
        data = response.json()
        assert data["email"] == "john@example.com"
        assert data["full_name"] == "John Doe"
        assert "id" in data
        assert "password_hash" not in data

    async def test_duplicate_email_registration(
        self, client: AsyncClient, test_user, mock_email: None
    ) -> None:
        response = await client.post(
            "/api/v1/auth/register",
            json={
                "full_name": "John Doe",
                "email": test_user.email,
                "password": "SecurePass123",
                "confirm_password": "SecurePass123",
            },
        )
        assert response.status_code == 409

    async def test_password_mismatch(
        self, client: AsyncClient, mock_email: None
    ) -> None:
        response = await client.post(
            "/api/v1/auth/register",
            json={
                "full_name": "John Doe",
                "email": "john@example.com",
                "password": "SecurePass123",
                "confirm_password": "DifferentPass123",
            },
        )
        assert response.status_code == 422

    async def test_weak_password(
        self, client: AsyncClient, mock_email: None
    ) -> None:
        response = await client.post(
            "/api/v1/auth/register",
            json={
                "full_name": "John Doe",
                "email": "john@example.com",
                "password": "short",
                "confirm_password": "short",
            },
        )
        assert response.status_code == 422


class TestLogin:
    async def test_successful_login(
        self, client: AsyncClient, test_user, mock_email: None
    ) -> None:
        response = await client.post(
            "/api/v1/auth/login",
            json={
                "email": test_user.email,
                "password": "TestPassword123",
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"
        assert "expires_in" in data

    async def test_invalid_password(
        self, client: AsyncClient, test_user, mock_email: None
    ) -> None:
        response = await client.post(
            "/api/v1/auth/login",
            json={
                "email": test_user.email,
                "password": "WrongPassword123",
            },
        )
        assert response.status_code == 401
        assert "Invalid" in response.json()["detail"]

    async def test_nonexistent_user_login(
        self, client: AsyncClient, mock_email: None
    ) -> None:
        response = await client.post(
            "/api/v1/auth/login",
            json={
                "email": "nonexistent@example.com",
                "password": "TestPassword123",
            },
        )
        assert response.status_code == 401


class TestAccessToken:
    async def test_protected_endpoint_with_valid_token(
        self, client: AsyncClient, test_user, mock_email: None
    ) -> None:
        login_response = await client.post(
            "/api/v1/auth/login",
            json={
                "email": test_user.email,
                "password": "TestPassword123",
            },
        )
        access_token = login_response.json()["access_token"]

        response = await client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["email"] == test_user.email
        assert data["full_name"] == test_user.full_name
        assert "password_hash" not in data

    async def test_protected_endpoint_without_token(
        self, client: AsyncClient
    ) -> None:
        response = await client.get("/api/v1/auth/me")
        assert response.status_code == 401

    async def test_protected_endpoint_with_invalid_token(
        self, client: AsyncClient
    ) -> None:
        response = await client.get(
            "/api/v1/auth/me",
            headers={"Authorization": "Bearer invalid-token"},
        )
        assert response.status_code == 401


class TestRefreshToken:
    async def test_refresh_token_rotation(
        self, client: AsyncClient, test_user, mock_email: None
    ) -> None:
        login_response = await client.post(
            "/api/v1/auth/login",
            json={
                "email": test_user.email,
                "password": "TestPassword123",
            },
        )
        refresh_token = login_response.json()["refresh_token"]

        refresh_response = await client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": refresh_token},
        )
        assert refresh_response.status_code == 200
        data = refresh_response.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["access_token"] != login_response.json()["access_token"]
        assert data["refresh_token"] != refresh_token

    async def test_refresh_with_revoked_token(
        self, client: AsyncClient, test_user, mock_email: None
    ) -> None:
        login_response = await client.post(
            "/api/v1/auth/login",
            json={
                "email": test_user.email,
                "password": "TestPassword123",
            },
        )
        refresh_token = login_response.json()["refresh_token"]

        await client.post(
            "/api/v1/auth/logout",
            json={"refresh_token": refresh_token},
        )

        refresh_response = await client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": refresh_token},
        )
        assert refresh_response.status_code == 401


class TestLogout:
    async def test_successful_logout(
        self, client: AsyncClient, test_user, mock_email: None
    ) -> None:
        login_response = await client.post(
            "/api/v1/auth/login",
            json={
                "email": test_user.email,
                "password": "TestPassword123",
            },
        )
        refresh_token = login_response.json()["refresh_token"]

        response = await client.post(
            "/api/v1/auth/logout",
            json={"refresh_token": refresh_token},
        )
        assert response.status_code == 200
        assert response.json()["message"] == "Logged out successfully"


class TestPasswordReset:
    async def test_forgot_password(
        self, client: AsyncClient, test_user, mock_email: None
    ) -> None:
        response = await client.post(
            "/api/v1/auth/forgot-password",
            json={"email": test_user.email},
        )
        assert response.status_code == 200

    async def test_forgot_password_nonexistent_email(
        self, client: AsyncClient, mock_email: None
    ) -> None:
        response = await client.post(
            "/api/v1/auth/forgot-password",
            json={"email": "nonexistent@example.com"},
        )
        assert response.status_code == 200

    async def test_reset_password(
        self,
        client: AsyncClient,
        test_user,
        db_session,
        mock_email: None,
    ) -> None:
        from src.apps.core.security import generate_otp, hash_otp
        from src.apps.db.models.password_reset_otp_model import PasswordResetOTP
        from datetime import datetime, timedelta, timezone

        otp = "123456"
        otp_hash = hash_otp(otp)
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)

        otp_record = PasswordResetOTP(
            user_id=test_user.id,
            otp_hash=otp_hash,
            expires_at=expires_at,
            attempts=0,
            is_used=False,
        )
        db_session.add(otp_record)
        await db_session.commit()

        response = await client.post(
            "/api/v1/auth/reset-password",
            json={
                "email": test_user.email,
                "otp": otp,
                "new_password": "NewSecurePass123",
                "confirm_password": "NewSecurePass123",
            },
        )
        assert response.status_code == 200
        assert response.json()["message"] == "Password reset successfully"

    async def test_reset_password_invalid_otp(
        self, client: AsyncClient, test_user, mock_email: None
    ) -> None:
        response = await client.post(
            "/api/v1/auth/reset-password",
            json={
                "email": test_user.email,
                "otp": "000000",
                "new_password": "NewSecurePass123",
                "confirm_password": "NewSecurePass123",
            },
        )
        assert response.status_code == 400


class TestUnauthorizedAccess:
    async def test_access_without_authentication(
        self, client: AsyncClient
    ) -> None:
        response = await client.get("/api/v1/auth/me")
        assert response.status_code == 401

    async def test_access_with_expired_token(
        self, client: AsyncClient
    ) -> None:
        expired_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMiLCJleHAiOjEsInR5cGUiOiJhY2Nlc3MifQ.invalid"
        response = await client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {expired_token}"},
        )
        assert response.status_code == 401
