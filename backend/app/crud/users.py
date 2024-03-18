from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select


from models.users import User  # type: ignore


async def get_user_by_id(db: AsyncSession, user_id: str):
    result = await db.execute(select(User).filter(User.id == user_id))
    user = result.scalars().first()
    return user
