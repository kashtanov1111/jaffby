from typing import Annotated
from pydantic import EmailStr

from fastapi import Depends, HTTPException, Body, status
from fastapi.security import APIKeyCookie, APIKeyHeader
from sqlalchemy.ext.asyncio import AsyncSession

from core.settings import settings
from core.security import verify_password
from core.utils import get_db_session, CustomRateLimiter
from crud.users import UserCRUD
from crud.auth import RefreshTokenCRUD
from models.users import User
from models.refresh_tokens import RefreshToken
from .classes import JWTToken


jwt_access_cookie_auth = APIKeyCookie(name="JWT")
jwt_refresh_cookie_auth = APIKeyCookie(name="JWT-refresh-token")
csrftoken_cookie_auth = APIKeyCookie(name="csrftoken")
if settings.DEBUG == False:
    csrftoken_header_auth = APIKeyHeader(name="X-CSRF-Token")
else:
    csrftoken_header_auth = lambda: "dev"  # type: ignore


GetDbSessionDep = Annotated[AsyncSession, Depends(get_db_session)]
EmailStrEmbeddedDep = Annotated[EmailStr, Body(embed=True)]
CustomRateLimiterDepends5 = Depends(CustomRateLimiter(times=5, hours=1))
CustomRateLimiterDepends10 = Depends(CustomRateLimiter(times=10, hours=1))
CustomRateLimiterDepends20 = Depends(CustomRateLimiter(times=20, hours=1))
CustomRateLimiterDepends30 = Depends(CustomRateLimiter(times=30, hours=1))


async def get_current_user(
    token: Annotated[str, Depends(jwt_access_cookie_auth)],
    db: GetDbSessionDep,
) -> User:
    id = await JWTToken(is_refresh=False).validate(token)
    user = await UserCRUD(db).get_by_id(id)
    if user is None:
        raise JWTToken.credentials_exception
    if not user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    return user


GetCurrentUserDep = Annotated[User, Depends(get_current_user)]


async def csrftoken_check(
    x_csrf_token: Annotated[str, Depends(csrftoken_header_auth)],
    csrftoken: Annotated[str, Depends(csrftoken_cookie_auth)],
) -> None:
    if x_csrf_token != csrftoken and settings.DEBUG == False:
        raise JWTToken.credentials_exception


async def validate_refresh_token_from_cookie(
    refresh_token: Annotated[str, Depends(jwt_refresh_cookie_auth)],
    db: GetDbSessionDep,
) -> RefreshToken:
    id = await JWTToken(is_refresh=True).validate(refresh_token)
    refresh_token_from_db = await RefreshTokenCRUD(db).get_by_id(id)
    if refresh_token_from_db is None or refresh_token_from_db.revoked == True:
        raise JWTToken.credentials_exception
    return refresh_token_from_db


ValidateRefreshTokenFromCookieDep = Annotated[
    RefreshToken, Depends(validate_refresh_token_from_cookie)
]


async def verify_password_for_important_changes(
    password: Annotated[str, Body(embed=True)],
    current_user: GetCurrentUserDep,
) -> User:
    if len(password) > settings.MAX_PASSWORD_LENGTH:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect password",
        )
    if not await verify_password(password, current_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect password",
        )
    return current_user


VerifyPasswordForImportantChangesDep = Annotated[
    User, Depends(verify_password_for_important_changes)
]
