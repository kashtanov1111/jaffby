import uuid
from uuid import UUID
from datetime import datetime, timedelta, timezone

from fastapi import Response, status, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from jose import jwt  # type: ignore

from core.settings import settings
from crud.users import get_user_by_username
from crud.auth import create_refresh_token
from schemas.auth import RefreshTokenCreateSchema
from models.users import User
from core.security import generate_csrf_token, verify_password


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
