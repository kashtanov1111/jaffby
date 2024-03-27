from fastapi import APIRouter
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Annotated

from fastapi import Depends, Body, HTTPException
from models.users import User
from schemas.users import UserUpdateSchema, UserSchema
from crud.users import UserCRUD
from .auth.dependencies import (
    get_current_user,
    csrftoken_check,
)
from core.utils import get_db_session


router = APIRouter()


@router.put(
    "/update",
    dependencies=[
        Depends(csrftoken_check),
    ],
    response_model=UserSchema,
)
async def update_user_profile_route(
    request_data: Annotated[UserUpdateSchema, Body(embed=False)],
    data: Annotated[tuple[User, AsyncSession], Depends(get_current_user)],
):
    current_user, db = data
    current_user.first_name = request_data.first_name  # type: ignore
    current_user.last_name = request_data.last_name  # type: ignore
    updated_user = await UserCRUD(db).update(current_user)
    return updated_user


@router.get("/{user_id}", response_model=UserSchema)
async def get_user_by_id_route(
    user_id: str, db: AsyncSession = Depends(get_db_session)
):
    db_user = await UserCRUD(db).get_by_id(user_id)
    if db_user is None or db_user.is_active == False:
        raise HTTPException(status_code=404, detail="User not found")
    return db_user
