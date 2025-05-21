from pydantic import AnyHttpUrl, BaseModel


class ProxyHeaders(BaseModel):
    dva_target: AnyHttpUrl
    oauth_access_token: str | None = None
    correlation_id: str | None = None
    x_mgo_provider_id: str | None
    x_mgo_service_id: int | None
    accept: str
