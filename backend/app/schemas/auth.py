from pydantic import BaseModel, ConfigDict, EmailStr
from uuid import UUID
from datetime import datetime


class RefreshTokenBaseSchema(BaseModel):
    id: UUID
    user_id: UUID
    token: str
    expires_at: datetime


class RefreshTokenCreateSchema(RefreshTokenBaseSchema):
    pass


class RefreshTokenSchema(RefreshTokenBaseSchema):
    revoked: bool

    model_config = ConfigDict(from_attributes=True)