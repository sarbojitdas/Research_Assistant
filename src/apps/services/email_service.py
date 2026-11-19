import asyncio
import logging
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from src.apps.core.config import settings

logger = logging.getLogger(__name__)

async def send_password_reset_otp(to_email: str, otp: str):
    if not settings.SENDGRID_API_KEY or not settings.SENDGRID_FROM_EMAIL:
        logger.warning("SendGrid not configured - logging OTP to console")
        logger.info("OTP for %s: %s", to_email, otp)
        return

    message = Mail(
        from_email=settings.SENDGRID_FROM_EMAIL,
        to_emails=to_email,
        subject="Password Reset OTP",
        plain_text_content=f"Your password reset OTP is: {otp}\nValid for 10 minutes."
    )
    
    client = SendGridAPIClient(api_key=settings.SENDGRID_API_KEY)

    await asyncio.to_thread(client.send, message)