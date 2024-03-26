from typing import Annotated, Any
from pydantic import EmailStr

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Response,
    BackgroundTasks,
    Body,
    status,
)
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession

from core.utils import get_db_session
from core.security import verify_password
from crud.users import UserCRUD
from crud.auth import TokenForEmailCRUD, RefreshTokenCRUD
from schemas.users import UserSchema, UserCreateSchema, UserPasswordResetSchema
from .utils import (
    authenticate_user,
    create_tokens_and_set_auth_cookies_in_response,
    clear_auth_cookies_in_response,
)
from .dependencies import (
    get_current_user,
    csrftoken_check,
    validate_refresh_token_from_cookie,
    verify_password_for_important_changes,
)
from models.users import User
from models.refresh_tokens import RefreshToken
from .classes import TokenForEmail

router = APIRouter()


@router.post("/login")
async def login_route(
    response: Response,
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    login_str = form_data.username  # could be email also
    user = await authenticate_user(db, login_str, form_data.password)
    await create_tokens_and_set_auth_cookies_in_response(db, str(user.id), response)
    return {"message": "Logged in successfully"}


@router.get("/me", response_model=UserSchema)
async def me_route(
    data: Annotated[tuple[User, AsyncSession], Depends(get_current_user)]
):
    return data[0]


@router.post("/register")
async def register_route(
    user: UserCreateSchema,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    user_crud = UserCRUD(db)
    db_user_by_email = await user_crud.get_by_email(user.email)
    if db_user_by_email:
        raise HTTPException(status_code=400, detail="Email already registered")
    db_user_by_username = await user_crud.get_by_username(user.username)
    if db_user_by_username:
        raise HTTPException(status_code=400, detail="Username already registered")
    created_user = await user_crud.create(user)
    token_for_email = TokenForEmail(
        is_for_password_reset=False, is_for_email_change=False
    )
    token = await token_for_email.generate_and_store(db, str(created_user.id))
    background_tasks.add_task(
        token_for_email.send_email, str(created_user.email), token
    )
    return {"message": "Confirmation email sent."}


@router.post("/refresh", dependencies=[Depends(csrftoken_check)])
async def refresh_token_route(
    response: Response,
    data: Annotated[
        tuple[RefreshToken, AsyncSession], Depends(validate_refresh_token_from_cookie)
    ],
):
    refresh_token_from_db, db = data
    await RefreshTokenCRUD(db).set_revoke_status_to_true(str(refresh_token_from_db.id))
    await create_tokens_and_set_auth_cookies_in_response(
        db, str(refresh_token_from_db.user_id), response
    )
    return {"message": "Successfully refreshed tokens."}


@router.post(
    "/logout",
    dependencies=[
        Depends(csrftoken_check),
        Depends(get_current_user),
    ],
)
async def logout_route(
    response: Response,
    data: Annotated[
        tuple[RefreshToken, AsyncSession], Depends(validate_refresh_token_from_cookie)
    ],
):
    refresh_token_from_db, db = data
    await RefreshTokenCRUD(db).set_revoke_status_to_true(str(refresh_token_from_db.id))
    await clear_auth_cookies_in_response(response)
    return {"message": "Successfully logged out"}


@router.post("/confirm-email")
async def confirm_email_route(
    data: Annotated[
        tuple[str, str, AsyncSession, Any],
        Depends(TokenForEmail(is_for_password_reset=False)),
    ]
):
    token_id, user_id, db, _ = data
    await TokenForEmailCRUD(db, is_for_password_reset=False).set_is_used_true(token_id)
    await UserCRUD(db).set_is_email_confirmed_and_is_active_true(user_id)
    return {"message": "Email was confirmed successfully."}


@router.post("/resend-email-confirmation")
async def resend_confirmation_email_route(
    email: Annotated[EmailStr, Body(embed=True)],
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db_session),
):
    user = await UserCRUD(db).get_by_email(email)
    if user and not user.is_email_confirmed:
        await TokenForEmailCRUD(
            db, is_for_password_reset=False
        ).set_is_used_true_on_all_tokens(str(user.id))
        token_for_email = TokenForEmail(
            is_for_password_reset=False, is_for_email_change=False
        )
        token = await token_for_email.generate_and_store(db, str(user.id))
        background_tasks.add_task(token_for_email.send_email, str(user.email), token)

    return {
        "message": "If an account with that email exists, a confirmation email has been sent."
    }


@router.post("/request-password-reset")
async def request_password_reset(
    email: Annotated[EmailStr, Body(embed=True)],
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db_session),
):
    user = await UserCRUD(db).get_by_email(email)
    if user and user.is_email_confirmed:
        token_for_email = TokenForEmail(is_for_password_reset=True)
        token = await token_for_email.generate_and_store(db, str(user.id))
        background_tasks.add_task(token_for_email.send_email, str(user.email), token)

    return {
        "message": "If an email address is associated with an account, a password reset link has been sent."
    }


@router.post("/reset-password")
async def reset_password_route(
    data: Annotated[
        tuple[str, str, AsyncSession, Any],
        Depends(TokenForEmail(is_for_password_reset=True)),
    ],
    request_data: UserPasswordResetSchema,
):
    new_password = request_data.password
    token_id, user_id, db, _ = data
    await TokenForEmailCRUD(db, is_for_password_reset=True).set_is_used_true(token_id)
    await UserCRUD(db).update_password(new_password, user_id)
    return {"message": "Password was successfully reset."}


@router.post(
    "/archive-account",
    dependencies=[
        Depends(csrftoken_check),
    ],
)
async def archive_account_route(
    response: Response,
    data1: Annotated[
        tuple[User, AsyncSession], Depends(verify_password_for_important_changes)
    ],
    data2: Annotated[
        tuple[RefreshToken, AsyncSession], Depends(validate_refresh_token_from_cookie)
    ],
):
    current_user, db = data1
    refresh_token_from_db, _ = data2
    await UserCRUD(db).set_is_active_false(str(current_user.id))
    await RefreshTokenCRUD(db).set_revoke_status_to_true(str(refresh_token_from_db.id))
    await clear_auth_cookies_in_response(response)
    return {"message": "Successfully archived"}


@router.post(
    "/request-email-change",
    dependencies=[
        Depends(csrftoken_check),
    ],
)
async def change_email_route(
    new_email: Annotated[EmailStr, Body(embed=True)],
    data: Annotated[
        tuple[User, AsyncSession], Depends(verify_password_for_important_changes)
    ],
    background_tasks: BackgroundTasks,
):
    current_user, db = data
    token_for_email = TokenForEmail(
        is_for_password_reset=False, is_for_email_change=True
    )
    token = await token_for_email.generate_and_store(
        db, str(current_user.id), new_email
    )
    background_tasks.add_task(token_for_email.send_email, new_email, token)
    return {
        "message": "Confirmation email sent. Please check your new email to confirm the email change."
    }


@router.post("/confirm-email-change")
async def confirm_email_change_route(
    data: Annotated[
        tuple[str, str, AsyncSession, Any],
        Depends(TokenForEmail(is_for_password_reset=False)),
    ]
):
    token_id, user_id, db, extra_data = data
    await TokenForEmailCRUD(db, is_for_password_reset=False).set_is_used_true(token_id)
    await UserCRUD(db).update_email(extra_data["new_email"], user_id)
    return {"message": "Email was confirmed successfully."}
