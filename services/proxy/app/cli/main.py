import typer

from app.bindings import ensure_bindings_configured
from app.medmij.commands import medmij_app

command_line_app = typer.Typer()
command_line_app.add_typer(medmij_app, name="medmij")


@command_line_app.callback()
def bootstrap() -> None:
    ensure_bindings_configured()


if __name__ == "__main__":
    command_line_app()
