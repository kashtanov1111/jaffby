from pydantic import EmailStr

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import update
from sqlalchemy.sql.expression import or_

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

    async def get_by_login_str(self, login_str: str) -> User | None:
        result = await self.db.execute(
            select(self.model).where(
                or_(self.model.username == login_str, self.model.email == login_str)
            )
        )
        user = result.scalars().first()
        return user

    async def create(self, user: UserCreateSchema) -> User:
        user_dict = user.model_dump()
        user_dict["hashed_password"] = await get_password_hash(user_dict["password"])
        del user_dict["password"]
        db_user = self.model(**user_dict)
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

    async def set_is_active_false(self, id: str) -> None:
        await self.db.execute(
            update(self.model).where(self.model.id == id).values(is_active=False)
        )
        await self.db.commit()

    async def set_is_active_true(self, id: str) -> None:
        await self.db.execute(
            update(self.model).where(self.model.id == id).values(is_active=True)
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

    async def update_email(self, new_email: EmailStr, id: str):
        await self.db.execute(
            update(self.model).where(self.model.id == id).values(email=new_email)
        )
        await self.db.commit()

    async def update_username(self, new_username: str, id: str):
        await self.db.execute(
            update(self.model).where(self.model.id == id).values(username=new_username)
        )
        await self.db.commit()

    async def update(self, user: User):
        self.db.add(user)
        await self.db.commit()
        await self.db.refresh(user)
        return user
