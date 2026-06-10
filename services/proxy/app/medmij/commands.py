import inject
import typer
from rich.console import Console

from app.medmij.services import MedMijWhitelistPuller

medmij_app = typer.Typer()
err_console = Console(stderr=True)


@medmij_app.command("pull-whitelist")
def pull_whitelist() -> None:
    whitelist_puller: MedMijWhitelistPuller = inject.instance(MedMijWhitelistPuller)
    print("Pulling MedMij whitelist hostnames")

    try:
        count = whitelist_puller.pull_and_refresh()
    except Exception as exception:
        err_console.print(
            f"[bold red] Failed to pull MedMij whitelist: {exception} [/bold red]"
        )
        raise typer.Exit(code=1)

    print(f"Pulled {count} MedMij whitelist hostnames")
