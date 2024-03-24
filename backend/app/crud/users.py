from pydantic import EmailStr

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from models.users import User
from schemas.users import UserCreateSchema
from core.security import get_password_hash


async def get_user_by_id(db: AsyncSession, user_id: str) -> User | None:
    result = await db.execute(select(User).filter(User.id == user_id))
    user = result.scalars().first()
    return user


async def get_user_by_email(db: AsyncSession, email: EmailStr) -> User | None:
    result = await db.execute(select(User).filter(User.email == email))
    user = result.scalars().first()
    return user


async def get_user_by_username(db: AsyncSession, username: str) -> User | None:
    result = await db.execute(select(User).filter(User.username == username))
    user = result.scalars().first()
    return user


async def create_user(db: AsyncSession, user: UserCreateSchema) -> User:
    hashed_password = await get_password_hash(user.password)
    db_user = User(
        email=user.email, username=user.username, hashed_password=hashed_password
    )
    db.add(db_user)
    await db.commit()
    await db.refresh(db_user)
    return db_user
