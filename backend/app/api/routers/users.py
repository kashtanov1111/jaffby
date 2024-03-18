from fastapi import APIRouter
from sqlalchemy.ext.asyncio import AsyncSession

from fastapi import Depends, HTTPException
from core.database import SessionLocal  # type: ignore
from crud.users import get_user_by_id  # type: ignore
from schemas.users import UserSchema  # type: ignore


router = APIRouter()


async def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@router.get("/{user_id}", response_model=UserSchema)
async def read_user(user_id: str, db: AsyncSession = Depends(get_db)):
    db_user = await get_user_by_id(db, user_id=user_id)
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return db_user
