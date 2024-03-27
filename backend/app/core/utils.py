import aiosmtplib  # type: ignore
from pydantic import EmailStr, Field
from typing import Annotated, Callable, Optional

from fastapi_limiter.depends import RateLimiter  # type: ignore

from email.message import EmailMessage
from core.settings import settings
from core.database import SessionLocal


async def get_db_session():
    async with SessionLocal() as session:
        yield session


async def send_email_async(recipient_email: EmailStr, subject: str, body: str) -> None:
    message = EmailMessage()
    message["From"] = str(settings.SMTP_HOST_USER)
    message["To"] = recipient_email
    message["Subject"] = subject
    message.set_content(body)

    if settings.DEBUG == True:
        print("------------------------------")
        print("------------------------------")
        print(f"You: {recipient_email} received an email, with this body:")
        print(message)
        print(body)
        print("------------------------------")
        print("------------------------------")
    else:
        await aiosmtplib.send(
            message,
            hostname=settings.SMTP_HOST,
            port=settings.SMTP_PORT,
            start_tls=True,
            username=settings.SMTP_HOST_USER,
            password=settings.SMTP_HOST_PASSWORD,
        )


class CustomRateLimiter(RateLimiter):
    def __init__(
        self,
        times: Annotated[int, Field(ge=0)] = 1,
        milliseconds: Annotated[int, Field(ge=-1)] = 0,
        seconds: Annotated[int, Field(ge=-1)] = 0,
        minutes: Annotated[int, Field(ge=-1)] = 0,
        hours: Annotated[int, Field(ge=-1)] = 0,
        identifier: Optional[Callable] = None,
        callback: Optional[Callable] = None,
    ):
        if settings.DEBUG:
            times = 10000
            seconds = 1
        super().__init__(
            times=times,
            milliseconds=milliseconds,
            seconds=seconds,
            minutes=minutes,
            hours=hours,
            identifier=identifier,
            callback=callback,
        )
