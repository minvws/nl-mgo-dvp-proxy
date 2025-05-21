from pydantic import BaseModel


class VersionInfo(BaseModel):
    release_version: str
    git_ref: str
