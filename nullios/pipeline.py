import tempfile
from dataclasses import dataclass
from enum import Enum, auto
from pathlib import Path
from typing import Callable

from nullios import analyzer, ipa, report, store
from nullios.errors import NulliosError
from nullios.ipa import IpaBundleManager
from nullios.store import resolve_target

DEFAULT_OUTPUT_DIR = Path.home() / "Desktop" / "nullios"


class Step(Enum):
    ACQUIRE = auto()
    EXTRACT = auto()
    ANALYZE = auto()
    REPORT = auto()
    DONE = auto()


@dataclass(frozen=True)
class StepUpdate:
    step: Step
    message: str


ProgressCallback = Callable[[StepUpdate], None]


def _noop(_: StepUpdate) -> None:
    return None


def run_local(
    ipa_path: Path,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
    on_progress: ProgressCallback = _noop,
) -> tuple[Path, Path]:
    manager = IpaBundleManager()
    try:
        on_progress(StepUpdate(Step.ACQUIRE, f"Loading IPA: {ipa_path}"))
        bundle = manager.open(ipa_path)

        on_progress(StepUpdate(Step.EXTRACT, f"Extracted bundle: {bundle.bundle_id}"))

        on_progress(StepUpdate(Step.ANALYZE, "Running static analysis"))
        result = analyzer.analyze(
            bundle,
            on_progress=lambda msg: on_progress(StepUpdate(Step.ANALYZE, msg)),
        )

        on_progress(StepUpdate(Step.REPORT, f"Writing reports to {output_dir}"))
        md_path, json_path = report.write_reports(result, output_dir)

        on_progress(StepUpdate(Step.DONE, f"Markdown: {md_path}\nJSON: {json_path}"))
        return md_path, json_path
    finally:
        manager.close()


def run_store(
    target: str,
    credentials: store.StoreCredentials | None = None,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
    on_progress: ProgressCallback = _noop,
) -> tuple[Path, Path]:
    bundle_id = resolve_target(target)
    on_progress(StepUpdate(Step.ACQUIRE, f"Resolved bundle id: {bundle_id}"))
    on_progress(StepUpdate(Step.ACQUIRE, f"Downloading from App Store: {bundle_id}"))
    ipa_path = store.download_ipa(bundle_id, credentials, output_dir / "ipa")
    on_progress(StepUpdate(Step.ACQUIRE, f"Saved IPA to {ipa_path}"))
    return run_local(ipa_path, output_dir, on_progress)


def run(
    target: str,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
    credentials: store.StoreCredentials | None = None,
    on_progress: ProgressCallback = _noop,
) -> tuple[Path, Path]:
    target_path = Path(target).expanduser()
    if target_path.exists() and target_path.suffix.lower() == ".ipa":
        return run_local(target_path, output_dir, on_progress)
    bundle_id = resolve_target(target)
    return run_store(bundle_id, credentials, output_dir, on_progress)
