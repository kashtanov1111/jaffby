from typing import Annotated

from fastapi import APIRouter, Depends, Body, HTTPException

from schemas.users import UserUpdateSchema, UserSchema
from crud.users import UserCRUD
from .auth.dependencies import (
    csrftoken_check,
    CustomRateLimiterDepends5,
    CustomRateLimiterDepends30,
    GetDbSessionDep,
    GetCurrentUserDep,
)

router = APIRouter()


@router.put(
    "/update",
    dependencies=[
        Depends(csrftoken_check),
        CustomRateLimiterDepends5,
    ],
)
async def update_user_profile_route(
    request_data: Annotated[UserUpdateSchema, Body(embed=False)],
    current_user: GetCurrentUserDep,
    db: GetDbSessionDep,
) -> UserSchema:
    current_user.first_name = request_data.first_name  # type: ignore
    current_user.last_name = request_data.last_name  # type: ignore
    updated_user = await UserCRUD(db).update(current_user)
    return updated_user


@router.get(
    "/{user_id}",
    dependencies=[CustomRateLimiterDepends30],
)
async def get_user_by_id_route(user_id: str, db: GetDbSessionDep) -> UserSchema:
    db_user = await UserCRUD(db).get_by_id(user_id)
    if db_user is None or db_user.is_active == False:
        raise HTTPException(status_code=404, detail="User not found")
    return db_user
