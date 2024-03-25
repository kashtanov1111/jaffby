from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql.expression import and_
from sqlalchemy.future import select
from sqlalchemy import update

from models.refresh_tokens import RefreshToken
from models.email_confirmation_tokens import EmailConfirmationToken
from models.password_reset_tokens import PasswordResetToken
from schemas.auth import RefreshTokenCreateSchema, TokenForEmailCreate


async def get_refresh_token_by_id(
    db: AsyncSession, refresh_token_id: str
) -> RefreshToken | None:
    result = await db.execute(
        select(RefreshToken).filter(RefreshToken.id == refresh_token_id)
    )
    refresh_token = result.scalars().first()
    return refresh_token


async def set_revoke_status_to_true_refresh_token(
    db: AsyncSession, refresh_token_id: str
) -> None:
    update_refresh_token = (
        update(RefreshToken)
        .where(RefreshToken.id == refresh_token_id)
        .values(revoked=True)
    )
    await db.execute(update_refresh_token)
    await db.commit()


async def create_refresh_token(
    db: AsyncSession, refresh_token: RefreshTokenCreateSchema
) -> RefreshToken:
    db_refresh_token = RefreshToken(
        id=refresh_token.id,
        user_id=refresh_token.user_id,
        token=refresh_token.token,
        expires_at=refresh_token.expires_at,
    )
    db.add(db_refresh_token)
    await db.commit()
    await db.refresh(db_refresh_token)
    return db_refresh_token


async def create_token_for_email(
    db: AsyncSession,
    token_for_email: TokenForEmailCreate,
    is_for_password_reset: bool,
) -> None:
    token_for_email_dict = token_for_email.model_dump()
    if is_for_password_reset:
        db_token_for_email = PasswordResetToken(**token_for_email_dict)
    else:
        db_token_for_email = EmailConfirmationToken(**token_for_email_dict)
    db.add(db_token_for_email)
    await db.commit()
    await db.refresh(db_token_for_email)


async def get_token_from_email_by_token(
    db: AsyncSession, token: str, is_for_password_reset: bool
) -> EmailConfirmationToken | PasswordResetToken | None:
    if is_for_password_reset:
        model = PasswordResetToken
    else:
        model = EmailConfirmationToken
    result = await db.execute(select(model).filter(model.token == token))
    token_from_email = result.scalars().first()
    return token_from_email


async def set_is_used_true_on_token_from_email(
    db: AsyncSession, token_id: str, is_for_password_reset: bool
) -> None:
    if is_for_password_reset:
        model = PasswordResetToken
    else:
        model = EmailConfirmationToken
    update_token = update(model).where(model.id == token_id).values(is_used=True)
    await db.execute(update_token)
    await db.commit()


async def set_is_used_true_on_all_email_confirmation_tokens_by_user_id(
    db: AsyncSession, user_id: str
):
    await db.execute(
        update(EmailConfirmationToken)
        .where(
            and_(
                EmailConfirmationToken.user_id == user_id,
                EmailConfirmationToken.is_used == False,
            )
        )
        .values(is_used=True)
    )
    await db.commit()
