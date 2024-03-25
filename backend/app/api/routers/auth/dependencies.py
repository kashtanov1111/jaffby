from typing import Annotated
from datetime import datetime, timezone

from fastapi import Depends, HTTPException, status
from fastapi.security import APIKeyCookie, APIKeyHeader
from jose import JWTError, jwt  # type: ignore
from sqlalchemy.ext.asyncio import AsyncSession


from core.settings import settings
from core.utils import get_db_session
from crud.users import get_user_by_id
from crud.auth import (
    get_refresh_token_by_id,
    set_revoke_status_to_true_refresh_token,
    get_token_from_email_by_token,
)
from models.users import User


jwt_access_cookie_auth = APIKeyCookie(name="JWT")
jwt_refresh_cookie_auth = APIKeyCookie(name="JWT-refresh-token")
csrftoken_cookie_auth = APIKeyCookie(name="csrftoken")
if settings.DEBUG == False:
    csrftoken_header_auth = APIKeyHeader(name="X-CSRF-Token")
else:
    csrftoken_header_auth = lambda: "dev"  # type: ignore


credentials_exception: HTTPException = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Could not validate credentials",
    headers={"WWW-Authenticate": "Cookie"},
)


async def validate_jwt_token(token: str, is_refresh: bool) -> str:
    if is_refresh == True:
        key_name = "jti"
    else:
        key_name = "sub"
    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.JWT_ENCODING_ALGORITHM],
            options={"leeway": 10},
        )
        id: str = payload.get(key_name)
        if id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    return id


async def get_current_user(
    token: Annotated[str, Depends(jwt_access_cookie_auth)],
    db: AsyncSession = Depends(get_db_session),
) -> User:
    id = await validate_jwt_token(token, is_refresh=False)
    user = await get_user_by_id(db, user_id=id)
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_user(
    current_user: Annotated[User, Depends(get_current_user)]
) -> User:
    if not current_user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


async def csrftoken_check(
    x_csrf_token: Annotated[str, Depends(csrftoken_header_auth)],
    csrftoken: Annotated[str, Depends(csrftoken_cookie_auth)],
) -> None:
    if x_csrf_token != csrftoken and settings.DEBUG == False:
        raise credentials_exception


async def validate_refresh_token_and_set_revoked_true(
    refresh_token: Annotated[str, Depends(jwt_refresh_cookie_auth)],
    db: AsyncSession = Depends(get_db_session),
) -> str:
    id = await validate_jwt_token(refresh_token, is_refresh=True)
    refresh_token_from_db = await get_refresh_token_by_id(db, refresh_token_id=id)
    if refresh_token_from_db is None:
        raise credentials_exception
    if refresh_token_from_db.revoked == True:
        raise credentials_exception
    await set_revoke_status_to_true_refresh_token(db, id)
    return str(refresh_token_from_db.user_id)


class TokenFromEmailValidator:
    def __init__(self, is_for_reset_password: bool):
        self.is_for_reset_password = is_for_reset_password

    async def __call__(
        self, token: str, db: AsyncSession = Depends(get_db_session)
    ) -> tuple[str, str, AsyncSession]:
        token_from_db = await get_token_from_email_by_token(
            db, token, self.is_for_reset_password
        )
        current_time = datetime.now(timezone.utc).replace(tzinfo=None)
        if (
            token_from_db is None
            or token_from_db.is_used == True
            or token_from_db.expires_at <= current_time
        ):
            detail = (
                "Wrong email confirmation token."
                if not self.is_for_reset_password
                else "Wrong password reset token."
            )
            raise HTTPException(status_code=400, detail=detail)
        return (
            str(token_from_db.id),
            str(token_from_db.user_id),
            db,
        )
