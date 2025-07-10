from fastapi import APIRouter

from app.utils import resolve_instance
from app.version.models import VersionInfo

router = APIRouter()


@router.get("/", response_model=VersionInfo)
def get_version(
    version_info: VersionInfo = resolve_instance(VersionInfo),
) -> VersionInfo:
    return version_info
