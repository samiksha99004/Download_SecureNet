"""
SecureNet Backend — Schema base classes

Every API schema inherits from CamelModel:
  * Python attributes are snake_case (they match the ORM columns, so
    `model_validate(orm_obj)` and `setattr(orm_obj, field, value)` just work).
  * JSON on the wire is camelCase (the frontend contract in src/types/*.ts).
  * Requests are accepted in either camelCase or snake_case.
"""

import uuid
from datetime import datetime
from typing import Annotated, Any

from pydantic import BaseModel, BeforeValidator, ConfigDict, PlainSerializer
from pydantic.alias_generators import to_camel

from app.utils.timeutil import to_iso_z


class CamelModel(BaseModel):
    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
        from_attributes=True,
        use_enum_values=False,
    )


def _uuid_to_str(value: Any) -> Any:
    return str(value) if isinstance(value, uuid.UUID) else value


# UUID columns are exposed to the frontend as plain strings.
IdStr = Annotated[str, BeforeValidator(_uuid_to_str)]

# Naive-UTC datetimes from the DB are sent as ISO strings ending in "Z".
UtcDatetime = Annotated[datetime, PlainSerializer(to_iso_z, return_type=str, when_used="json")]
