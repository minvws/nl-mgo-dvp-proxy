from dataclasses import dataclass


@dataclass(frozen=True)
class VersionInfo:
    version: str
    git_ref: str
