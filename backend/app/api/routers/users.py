import asyncio

from fastapi import APIRouter, status
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Callable, Annotated

from fastapi import Depends, HTTPException
from schemas.users import UserSchema, UserCreateSchema
from .auth.dependencies import (
    get_current_user,
    csrftoken_check,
)

router = APIRouter()


@router.put(
    "/update_user_profile",
    dependencies=[
        Depends(get_current_user),
        Depends(csrftoken_check),
    ],
)
async def update_user_profile_route():
    return "fake updated user profile alright"


# @router.get("/{user_id}", response_model=UserSchema)
# async def get_user_by_id_route(user_id: str, db: AsyncSession = Depends(get_session)):
#     db_user = await get_user_by_id(db, user_id=user_id)
#     if db_user is None:
#         raise HTTPException(status_code=404, detail="User not found")
#     return db_user
