from fastapi import HTTPException
from inject import autoparams
from starlette.status import HTTP_400_BAD_REQUEST

from app.security.dva_target.exceptions import DvaTargetAssertionError
from app.security.dva_target.services import DvaTargetAssertionParser


@autoparams("dva_target_assertion_parser")
def parsed_dva_target_url(
    dva_target_assertion_parser: DvaTargetAssertionParser,
    dva_target: str,
) -> str:
    try:
        return dva_target_assertion_parser.parse(serialized_jwe=dva_target)
    except DvaTargetAssertionError as e:
        raise HTTPException(
            status_code=HTTP_400_BAD_REQUEST,
            detail="Failed to parse DVA target",
        ) from e
