import secrets
from uuid import UUID
from datetime import datetime, timedelta, timezone
from pydantic import EmailStr

from fastapi import status, HTTPException, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from jose import JWTError, jwt  # type: ignore
from sqlalchemy.ext.asyncio import AsyncSession

from core.settings import settings
from crud.auth import TokenForEmailCRUD
from schemas.auth import TokenForEmailCreateSchema
from core.security import generate_csrf_token, verify_password
from core.utils import send_email_async, get_db_session


class JWTToken:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Cookie"},
    )

    def __init__(self, is_refresh: bool):
        if is_refresh:
            self.key_name = "jti"
            self.exp_timedelta = timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
        else:
            self.key_name = "sub"
            self.exp_timedelta = timedelta(seconds=settings.ACCESS_TOKEN_EXPIRE_SECONDS)
        self.key = settings.SECRET_KEY
        self.algorithm = settings.JWT_ENCODING_ALGORITHM

    async def create(self, id: str) -> tuple[str, datetime]:
        expire = datetime.now(timezone.utc) + self.exp_timedelta
        jwt_token = jwt.encode(
            {self.key_name: id, "exp": expire},
            self.key,
            algorithm=self.algorithm,
        )
        return jwt_token, expire.replace(tzinfo=None)

    async def validate(self, token: str) -> str:
        try:
            payload = jwt.decode(
                token,
                self.key,
                algorithms=[self.algorithm],
                options={"leeway": 10},
            )
            id: str = payload.get(self.key_name)
            if id is None:
                raise self.credentials_exception
        except JWTError:
            raise self.credentials_exception
        return id


class TokenForEmail:
    def __init__(self, is_for_password_reset: bool):
        if is_for_password_reset:
            self.exp_timedelta = timedelta(
                minutes=settings.PASSWORD_RESET_TOKEN_EXPIRE_MINUTES
            )
        else:
            self.exp_timedelta = timedelta(
                hours=settings.EMAIL_CONFIRMATION_TOKEN_EXPIRE_HOURS
            )
        self.is_for_password_reset = is_for_password_reset

    async def generate_and_store(self, db: AsyncSession, user_id: str) -> str:
        token = secrets.token_urlsafe()
        created_at_with_timezone = datetime.now(timezone.utc)
        expires_at = created_at_with_timezone + self.exp_timedelta

        expires_at = expires_at.replace(tzinfo=None)
        created_at = created_at_with_timezone.replace(tzinfo=None)

        token_for_email_to_db = TokenForEmailCreateSchema(
            token=token,
            user_id=UUID(user_id),
            created_at=created_at,
            expires_at=expires_at,
        )
        await TokenForEmailCRUD(db, self.is_for_password_reset).create(
            token_for_email_to_db
        )
        return token

    async def send_email(self, email: EmailStr, token: str) -> None:
        if settings.DEBUG == True:
            url_with_token = "http://localhost"
        else:
            url_with_token = f"https://{settings.DOMAIN_NAME}"
        url_with_token += settings.API_VERSION_STR
        if self.is_for_password_reset:
            url_with_token += f"/reset-password?token={token}"
            subject = "Reset your password"
            body = f"Please click the following link to reset your password: {url_with_token}"
        else:
            url_with_token += f"/confirm-email?token={token}"
            subject = "Confirm your email"
            body = f"Please click the following link to confirm your email address: {url_with_token}"
        await send_email_async(recipient_email=email, subject=subject, body=body)

    async def __call__(
        self, token: str, db: AsyncSession = Depends(get_db_session)
    ) -> tuple[str, str, AsyncSession]:
        """Validates token for email"""
        token_from_db = await TokenForEmailCRUD(
            db, self.is_for_password_reset
        ).get_by_token(token)
        current_time = datetime.now(timezone.utc).replace(tzinfo=None)
        if (
            token_from_db is None
            or token_from_db.is_used == True
            or token_from_db.expires_at <= current_time
        ):
            detail = (
                "Wrong email confirmation token."
                if not self.is_for_password_reset
                else "Wrong password reset token."
            )
            raise HTTPException(status_code=400, detail=detail)
        return (
            str(token_from_db.id),
            str(token_from_db.user_id),
            db,
        )