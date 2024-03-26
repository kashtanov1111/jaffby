from pydantic import EmailStr

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import update

from models.users import User
from schemas.users import UserCreateSchema
from core.security import get_password_hash


class UserCRUD:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.model = User

    async def get_by_id(self, id: str) -> User | None:
        result = await self.db.execute(select(self.model).filter(self.model.id == id))
        user = result.scalars().first()
        return user

    async def get_by_email(self, email: EmailStr) -> User | None:
        result = await self.db.execute(
            select(self.model).filter(self.model.email == email)
        )
        user = result.scalars().first()
        return user

    async def get_by_username(self, username: str) -> User | None:
        result = await self.db.execute(
            select(self.model).filter(self.model.username == username)
        )
        user = result.scalars().first()
        return user

    async def create(self, user: UserCreateSchema) -> User:
        hashed_password = await get_password_hash(user.password)
        db_user = self.model(
            email=user.email, username=user.username, hashed_password=hashed_password
        )
        self.db.add(db_user)
        await self.db.commit()
        await self.db.refresh(db_user)
        return db_user

    async def set_is_email_confirmed_and_is_active_true(self, id: str) -> None:
        await self.db.execute(
            update(self.model)
            .where(self.model.id == id)
            .values(is_email_confirmed=True, is_active=True)
        )
        await self.db.commit()

    async def update_password(self, new_password: str, id: str):
        hashed_password = await get_password_hash(new_password)
        await self.db.execute(
            update(self.model)
            .where(self.model.id == id)
            .values(hashed_password=hashed_password)
        )
        await self.db.commit()
