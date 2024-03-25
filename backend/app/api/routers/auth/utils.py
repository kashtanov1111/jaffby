import secrets
import uuid
from uuid import UUID
from datetime import datetime, timedelta, timezone
from pydantic import EmailStr

from fastapi import Response, status, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from jose import jwt  # type: ignore

from core.settings import settings
from crud.users import get_user_by_username
from crud.auth import create_refresh_token, create_token_for_email
from schemas.auth import RefreshTokenCreateSchema, TokenForEmailCreate
from models.users import User
from core.security import generate_csrf_token, verify_password
from core.utils import send_email_async


async def clear_auth_cookies_in_response(response: Response) -> None:
    response.delete_cookie(key="JWT", httponly=True, secure=True, samesite="lax")
    response.delete_cookie(
        key="JWT-refresh-token", httponly=True, secure=True, samesite="lax"
    )
    response.delete_cookie(key="csrftoken", secure=True, samesite="lax")


async def set_auth_cookies_in_response(
    response: Response, access_token: str, refresh_token: str
) -> None:
    # max_age_refresh_token = 5
    max_age_refresh_token = settings.REFRESH_TOKEN_EXPIRE_DAYS * 86400
    response.set_cookie(
        key="JWT",
        value=access_token,
        httponly=True,
        secure=True,
        samesite="lax",
        max_age=settings.ACCESS_TOKEN_EXPIRE_SECONDS,
    )
    response.set_cookie(
        key="JWT-refresh-token",
        value=refresh_token,
        httponly=True,
        secure=True,
        samesite="lax",
        max_age=max_age_refresh_token,
    )
    response.set_cookie(
        key="csrftoken",
        value=await generate_csrf_token(),
        secure=True,
        samesite="lax",
        max_age=settings.ACCESS_TOKEN_EXPIRE_SECONDS,
    )


incorrect_username_or_password_exception = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Incorrect username or password",
    headers={"WWW-Authenticate": "Cookie"},
)


async def authenticate_user(db: AsyncSession, username: str, password: str) -> User:
    user = await get_user_by_username(db, username)
    if not user:
        raise incorrect_username_or_password_exception
    if not await verify_password(password, user.hashed_password):
        raise incorrect_username_or_password_exception
    return user


async def create_jwt_token(
    data: dict, token_timedelta: timedelta
) -> tuple[str, datetime]:
    expire = datetime.now(timezone.utc) + token_timedelta
    data.update({"exp": expire})
    jwt_token = jwt.encode(
        data,
        settings.SECRET_KEY,
        algorithm=settings.JWT_ENCODING_ALGORITHM,
    )
    expire_naive = expire.replace(tzinfo=None)
    return jwt_token, expire_naive


async def create_tokens_and_set_auth_cookies_in_response(
    db: AsyncSession, user_id: str, response: Response
) -> None:
    access_token, _ = await create_jwt_token(
        {"sub": user_id}, timedelta(seconds=settings.ACCESS_TOKEN_EXPIRE_SECONDS)
    )
    refresh_token_uuid = str(uuid.uuid4())
    refresh_token, refresh_token_expire = await create_jwt_token(
        {"jti": refresh_token_uuid},
        # timedelta(seconds=5),
        timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
    )
    refresh_token_to_db = RefreshTokenCreateSchema(
        id=UUID(refresh_token_uuid),
        user_id=UUID(user_id),
        token=refresh_token,
        expires_at=refresh_token_expire,
    )
    await create_refresh_token(db, refresh_token_to_db)
    await set_auth_cookies_in_response(response, access_token, refresh_token)


async def generate_and_store_token_for_email(
    db: AsyncSession, user_id: str, is_for_password_reset: bool
) -> str:
    if is_for_password_reset:
        exp_timedelta = timedelta(minutes=settings.PASSWORD_RESET_TOKEN_EXPIRE_MINUTES)
    else:
        exp_timedelta = timedelta(hours=settings.EMAIL_CONFIRMATION_TOKEN_EXPIRE_HOURS)
    token = secrets.token_urlsafe()
    created_at_with_timezone = datetime.now(timezone.utc)
    expires_at = created_at_with_timezone + exp_timedelta

    expires_at = expires_at.replace(tzinfo=None)
    created_at = created_at_with_timezone.replace(tzinfo=None)

    token_for_email_to_db = TokenForEmailCreate(
        token=token, user_id=UUID(user_id), created_at=created_at, expires_at=expires_at
    )
    await create_token_for_email(db, token_for_email_to_db, is_for_password_reset)
    return token


async def send_email_with_token(
    email: EmailStr, token: str, is_for_reset_password: bool
) -> None:
    if settings.DEBUG == True:
        url_with_token = "http://localhost"
    else:
        url_with_token = f"https://{settings.DOMAIN_NAME}"
    url_with_token += settings.API_VERSION_STR
    if is_for_reset_password:
        url_with_token += f"/reset-password?token={token}"
        subject = "Reset your password"
        body = (
            f"Please click the following link to reset your password: {url_with_token}"
        )
    else:
        url_with_token += f"/confirm-email?token={token}"
        subject = "Confirm your email"
        body = f"Please click the following link to confirm your email address: {url_with_token}"
    await send_email_async(recipient_email=email, subject=subject, body=body)
