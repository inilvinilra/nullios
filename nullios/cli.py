import argparse
import os
import sys
from pathlib import Path

from rich.console import Console
from rich.panel import Panel

from nullios import pipeline
from nullios.errors import NulliosError
from nullios.store import StoreCredentials


BANNER = r"""[bold cyan]
 _   _  ___  _   _  _____
| \ | |/ _ \| | | ||_   _|
|  \| | | | | | | |  | |
| . ` | | | | | | |  | |
| |\  | |_| | |_| | _| |_
|_| \_|\___/ \___/ |_____|
[/bold cyan]
[dim]iOS static analysis workbench[/dim]
"""


def _run_headless(target: str, output_dir: Path, credentials: StoreCredentials | None) -> int:
    console = Console()
    console.print(BANNER)

    def on_progress(update: pipeline.StepUpdate) -> None:
        console.print(f"[cyan]•[/] {update.message}")

    try:
        md_path, json_path = pipeline.run(target, output_dir, credentials, on_progress=on_progress)
    except NulliosError as exc:
        console.print(Panel(f"[bold red]Error:[/] {exc}", title="nullios", border_style="red"))
        return 1

    console.print(Panel(
        f"[bold green]Analysis complete.[/]\n[white]{md_path}\n{json_path}[/white]",
        title="Reports",
        border_style="green",
    ))
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="nullios",
        description="iOS application acquisition and static analysis workbench",
    )
    parser.add_argument(
        "target",
        nargs="?",
        help="Path to an .ipa file, or an App Store bundle id. Omit to launch the TUI.",
    )
    parser.add_argument(
        "-o", "--output-dir",
        default=str(pipeline.DEFAULT_OUTPUT_DIR),
        help=f"Directory for analysis reports (default: {pipeline.DEFAULT_OUTPUT_DIR})",
    )
    parser.add_argument(
        "--apple-id",
        default=os.getenv("NULLIOS_APPLE_ID"),
        help="Apple ID for App Store downloads (or set NULLIOS_APPLE_ID)",
    )
    parser.add_argument(
        "--apple-password",
        default=os.getenv("NULLIOS_APPLE_PASSWORD"),
        help="Apple ID password for App Store downloads (or set NULLIOS_APPLE_PASSWORD)",
    )
    args = parser.parse_args()

    credentials = None
    if args.apple_id and args.apple_password:
        credentials = StoreCredentials(args.apple_id, args.apple_password)

    if args.target is None:
        from nullios.tui import run as run_tui
        run_tui()
        return

    sys.exit(_run_headless(args.target, Path(args.output_dir).expanduser(), credentials))


if __name__ == "__main__":
    main()
