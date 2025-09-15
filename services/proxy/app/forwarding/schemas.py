from typing import Optional
from pydantic import BaseModel, AnyHttpUrl, Field, ConfigDict


class ForwardingRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    dva_target: AnyHttpUrl = Field(
        ...,
        alias="X-MGO-DVA-TARGET",  # Use string literal for mypy
    )
    oauth_access_token: Optional[str] = Field(
        None,
        alias="X-MGO-ACCESS-TOKEN",  # Use string literal for mypy
    )
    correlation_id: Optional[str] = Field(
        None,
        alias="X-Correlation-ID",  # Use string literal for mypy
        min_length=1,
    )
    x_mgo_provider_id: Optional[str] = Field(
        None,
        alias="X-MGO-HEALTHCARE-PROVIDER-ID",  # Use string literal for mypy
    )
    x_mgo_service_id: Optional[int] = Field(
        None,
        alias="X-MGO-DATASERVICE-ID",  # Use string literal for mypy
    )
    accept: Optional[str] = Field(None, alias="Accept")
