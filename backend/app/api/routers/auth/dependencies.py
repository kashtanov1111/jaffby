from typing import Annotated
from datetime import datetime, timezone

from fastapi import Depends, HTTPException, status
from fastapi.security import APIKeyCookie, APIKeyHeader
from jose import JWTError, jwt  # type: ignore
from sqlalchemy.ext.asyncio import AsyncSession


from core.settings import settings
from core.utils import get_db_session
from crud.users import UserCRUD
from crud.auth import RefreshTokenCRUD, TokenForEmailCRUD
from models.users import User
from .classes import JWTToken


jwt_access_cookie_auth = APIKeyCookie(name="JWT")
jwt_refresh_cookie_auth = APIKeyCookie(name="JWT-refresh-token")
csrftoken_cookie_auth = APIKeyCookie(name="csrftoken")
if settings.DEBUG == False:
    csrftoken_header_auth = APIKeyHeader(name="X-CSRF-Token")
else:
    csrftoken_header_auth = lambda: "dev"  # type: ignore


async def get_current_user(
    token: Annotated[str, Depends(jwt_access_cookie_auth)],
    db: AsyncSession = Depends(get_db_session),
) -> User:
    id = await JWTToken(is_refresh=False).validate(token)
    user = await UserCRUD(db).get_by_id(id)
    if user is None:
        raise JWTToken.credentials_exception
    if not user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    return user


async def csrftoken_check(
    x_csrf_token: Annotated[str, Depends(csrftoken_header_auth)],
    csrftoken: Annotated[str, Depends(csrftoken_cookie_auth)],
) -> None:
    if x_csrf_token != csrftoken and settings.DEBUG == False:
        raise JWTToken.credentials_exception


async def validate_refresh_token_and_set_revoked_true(
    refresh_token: Annotated[str, Depends(jwt_refresh_cookie_auth)],
    db: AsyncSession = Depends(get_db_session),
) -> tuple[str, AsyncSession]:
    id = await JWTToken(is_refresh=True).validate(refresh_token)
    refresh_token_crud = RefreshTokenCRUD(db)
    refresh_token_from_db = await refresh_token_crud.get_by_id(id)
    if refresh_token_from_db is None or refresh_token_from_db.revoked == True:
        raise JWTToken.credentials_exception
    await refresh_token_crud.set_revoke_status_to_true(id)
    return str(refresh_token_from_db.user_id), db
