from fastapi import APIRouter, Response

from app.utils import resolve_instance
from app.version.models import VersionInfo

router = APIRouter()


@router.get("/")
def get_version(version_info: VersionInfo = resolve_instance(VersionInfo)) -> Response:
    return Response(
        f"Release version: {version_info.release_version}\nGit ref: {version_info.git_ref}"
    )
