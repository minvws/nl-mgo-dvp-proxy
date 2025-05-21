import inject
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from .authentication.router import router as auth_router
from .bindings import configure_bindings
from .config.models import AppConfig
from .constants import APP_NAME
from .docs.router import router as docs_router
from .exception_handlers import ExceptionHandlers
from .forwarding.router import router as forwarding_router
from .oidc.router import router as oidc_router
from .telemetry.jaeger_provider import setup_jaeger
from .utils import root_path
from .version.models import VersionInfo
from .version.router import router as index_router


def create_app() -> FastAPI:
    if not inject.is_configured():
        inject.configure(
            lambda binder: configure_bindings(binder=binder, config_file="app.conf"),
        )

    version_info: VersionInfo = inject.instance(VersionInfo)
    app_config: AppConfig = inject.instance(AppConfig)

    app = FastAPI(
        title=APP_NAME,
        version=version_info.release_version,
        docs_url=None,
        redoc_url=None,
    )

    app.mount("/static", StaticFiles(directory=root_path("static")), name="static")

    ExceptionHandlers.load_handlers(app)
    setup_jaeger(app)

    for router in [
        auth_router,
        docs_router,
        index_router,
        oidc_router,
        forwarding_router,
    ]:
        app.include_router(router)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_headers=["*"],
        allow_methods=["*"],
    )

    return app
