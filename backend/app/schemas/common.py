"""
SecureNet Backend — Common Schemas

Shared request/response models used across multiple endpoints.
"""

from typing import Generic, TypeVar, List, Optional

from pydantic import BaseModel

from app.schemas.base import CamelModel

T = TypeVar("T")


class PaginatedResponse(CamelModel, Generic[T]):
    """Generic paginated response matching the frontend contract"""
    data: List[T]
    total: int
    page: int
    page_size: int
    total_pages: int


class MessageResponse(BaseModel):
    """Simple message response"""
    message: str


class ApiError(BaseModel):
    """Structured error response (every error the API returns has this shape)"""
    status: int
    code: str
    message: str
    details: Optional[dict] = None
