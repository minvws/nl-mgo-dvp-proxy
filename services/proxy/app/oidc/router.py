from json import loads as json_decode

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse, RedirectResponse

from app.security.services import Encrypter
from app.utils import resolve_instance

from .schemas import ContinueRequest, StartRequest, State
from .services import (
    ClientCallbackUrlDecorator,
    VadAuthorizationUrlProvider,
    VadUserinfoProvider,
)

router = APIRouter(
    prefix="/oidc",
    tags=["OIDC"],
)


@router.post("/start")
def oidc_start(
    request: StartRequest,
    vad_authz_url_provider: VadAuthorizationUrlProvider = resolve_instance(
        VadAuthorizationUrlProvider
    ),
) -> JSONResponse:
    vad_authz_url = vad_authz_url_provider.invoke(str(request.client_callback_url))

    return JSONResponse({"authz_url": vad_authz_url})


@router.get("/callback")
def oidc_callback(
    request: ContinueRequest = Depends(),
    vad_userinfo_provider: VadUserinfoProvider = resolve_instance(VadUserinfoProvider),
    encrypter: Encrypter = resolve_instance(Encrypter),
    client_callback_url_decorator: ClientCallbackUrlDecorator = resolve_instance(
        ClientCallbackUrlDecorator
    ),
) -> RedirectResponse:
    state = State(**json_decode(encrypter.decrypt(request.state)))
    userinfo = vad_userinfo_provider.invoke(request.code, state)
    client_callback_url = client_callback_url_decorator.decorate_with_userinfo_data(
        userinfo, state
    )

    return RedirectResponse(status_code=302, url=client_callback_url)
