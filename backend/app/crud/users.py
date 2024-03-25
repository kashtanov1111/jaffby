from pydantic import EmailStr

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import update

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


async def set_is_email_confirmed_and_is_active_true_on_user(
    db: AsyncSession, user_id: str
) -> None:
    update_user = (
        update(User)
        .where(User.id == user_id)
        .values(is_email_confirmed=True, is_active=True)
    )
    await db.execute(update_user)
    await db.commit()


async def update_user_password(db: AsyncSession, new_password: str, user_id: str):
    hashed_password = await get_password_hash(new_password)
    await db.execute(
        update(User).where(User.id == user_id).values(hashed_password=hashed_password)
    )
    await db.commit()
