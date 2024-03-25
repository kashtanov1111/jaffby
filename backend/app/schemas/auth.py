from pydantic import BaseModel, ConfigDict
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


class TokenForEmailBase(BaseModel):
    token: str
    user_id: UUID
    created_at: datetime
    expires_at: datetime


class TokenForEmailCreate(TokenForEmailBase):
    pass


class TokenForEmail(TokenForEmailBase):
    id: UUID
    id_used: bool
