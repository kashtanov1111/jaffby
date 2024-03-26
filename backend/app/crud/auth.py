from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql.expression import and_
from sqlalchemy.future import select
from sqlalchemy import update

from models.refresh_tokens import RefreshToken
from models.email_confirmation_tokens import EmailConfirmationToken
from models.password_reset_tokens import PasswordResetToken
from schemas.auth import (
    RefreshTokenCreateSchema,
    EmailConfirmationCreateSchema,
    PasswordResetCreateSchema,
)


class RefreshTokenCRUD:

    def __init__(self, db: AsyncSession):
        self.db = db
        self.model = RefreshToken

    async def get_by_id(self, id: str) -> RefreshToken | None:
        result = await self.db.execute(select(self.model).filter(self.model.id == id))
        refresh_token = result.scalars().first()
        return refresh_token

    async def set_revoke_status_to_true(self, id: str) -> None:
        await self.db.execute(
            update(self.model).where(self.model.id == id).values(revoked=True)
        )
        await self.db.commit()

    async def create(self, token: RefreshTokenCreateSchema) -> None:
        token_dict = token.model_dump()
        db_token = self.model(**token_dict)
        self.db.add(db_token)
        await self.db.commit()


class TokenForEmailCRUD:
    def __init__(
        self,
        db: AsyncSession,
        is_for_password_reset: bool,
    ):
        if is_for_password_reset:
            self.model = PasswordResetToken
        else:
            self.model = EmailConfirmationToken
        self.db = db

    async def create(
        self, token: EmailConfirmationCreateSchema | PasswordResetCreateSchema
    ) -> None:
        token_dict = token.model_dump()
        db_token = self.model(**token_dict)
        self.db.add(db_token)
        await self.db.commit()

    async def get_by_token(
        self, token: str
    ) -> EmailConfirmationToken | PasswordResetToken | None:
        result = await self.db.execute(
            select(self.model).filter(self.model.token == token)
        )
        token_result = result.scalars().first()
        return token_result

    async def set_is_used_true(self, token_id: str) -> None:
        await self.db.execute(
            update(self.model).where(self.model.id == token_id).values(is_used=True)
        )
        await self.db.commit()

    async def set_is_used_true_on_all_tokens(self, user_id: str) -> None:
        await self.db.execute(
            update(self.model)
            .where(
                and_(
                    self.model.user_id == user_id,
                    self.model.is_used == False,
                )
            )
            .values(is_used=True)
        )
        await self.db.commit()
