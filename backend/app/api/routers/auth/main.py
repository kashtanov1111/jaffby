from typing import Annotated
from pydantic import EmailStr

from fastapi import APIRouter, Depends, HTTPException, Response, BackgroundTasks, Body
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession

from core.utils import get_db_session
from crud.users import UserCRUD
from crud.auth import TokenForEmailCRUD
from schemas.users import UserSchema, UserCreateSchema, UserPasswordResetSchema
from .utils import (
    authenticate_user,
    create_tokens_and_set_auth_cookies_in_response,
    clear_auth_cookies_in_response,
)
from .dependencies import (
    get_current_user,
    validate_refresh_token_and_set_revoked_true,
    csrftoken_check,
)
from models.users import User
from .classes import TokenForEmail

router = APIRouter()


@router.post("/login")
async def login_route(
    response: Response,
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    user = await authenticate_user(db, form_data.username, form_data.password)
    await create_tokens_and_set_auth_cookies_in_response(db, str(user.id), response)
    return {"message": "Logged in successfully"}


@router.get("/me", response_model=UserSchema)
async def me_route(current_user: Annotated[User, Depends(get_current_user)]):
    return current_user


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
    token_for_email = TokenForEmail(is_for_password_reset=False)
    token = await token_for_email.generate_and_store(db, str(created_user.id))
    background_tasks.add_task(
        token_for_email.send_email, str(created_user.email), token
    )
    return {"message": "Confirmation email sent."}


@router.post("/refresh", dependencies=[Depends(csrftoken_check)])
async def refresh_token_route(
    response: Response,
    data: Annotated[
        tuple[str, AsyncSession], Depends(validate_refresh_token_and_set_revoked_true)
    ],
):
    user_id, db = data
    await create_tokens_and_set_auth_cookies_in_response(db, user_id, response)
    return {"message": "Successfully refreshed tokens."}


@router.post(
    "/logout",
    dependencies=[
        Depends(csrftoken_check),
        Depends(get_current_user),
        Depends(validate_refresh_token_and_set_revoked_true),
    ],
)
async def logout_route(response: Response):
    await clear_auth_cookies_in_response(response)
    return {"message": "Successfully logged out"}


@router.post("/confirm-email")
async def confirm_email_route(
    data: Annotated[
        tuple[str, str, AsyncSession],
        Depends(TokenForEmail(is_for_password_reset=False)),
    ]
):
    token_id, user_id, db = data
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
        token_for_email = TokenForEmail(is_for_password_reset=False)
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
        tuple[str, str, AsyncSession],
        Depends(TokenForEmail(is_for_password_reset=True)),
    ],
    request_data: UserPasswordResetSchema,
):
    new_password = request_data.password
    token_id, user_id, db = data
    await TokenForEmailCRUD(db, is_for_password_reset=True).set_is_used_true(token_id)
    await UserCRUD(db).update_password(new_password, user_id)
    return {"message": "Password was successfully reset."}
