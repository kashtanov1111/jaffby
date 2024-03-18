from pydantic import BaseModel, ConfigDict
from uuid import UUID
from datetime import datetime


class UserBaseSchema(BaseModel):
    email: str
    username: str


class UserCreateSchema(UserBaseSchema):
    password: str


class UserSchema(UserBaseSchema):
    id: UUID
    is_active: bool
    first_name: str
    last_name: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
