from pathlib import Path

from textual import work
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    ListItem,
    ListView,
    RichLog,
    Static,
    TabbedContent,
    TabPane,
)

from nullios import analyzer, pipeline
from nullios.analyzer import AnalysisResult
from nullios.errors import NulliosError
from nullios.store import StoreCredentials

CSS_PATH = Path(__file__).with_name("tui.tcss")


class NulliosApp(App):
    CSS_PATH = CSS_PATH
    TITLE = "nullios"
    BINDINGS = [
        ("q", "quit", "Quit"),
        ("ctrl+c", "quit", "Quit"),
    ]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(id="app-grid"):
            with Vertical(id="sidebar"):
                yield Static("nullios", id="brand")
                yield Input(placeholder="IPA path or bundle id", id="target_input")
                yield Input(placeholder="Apple ID (optional)", id="apple_id_input")
                yield Input(placeholder="Apple password (optional)", id="apple_password_input", password=True)
                yield Button("Load IPA", id="load_btn", variant="primary")
                yield Button("Download", id="download_btn", variant="success")
                yield Button("Analyze", id="analyze_btn", variant="warning")
                yield Button("Open Report", id="report_btn", variant="default")
                yield Static("Status: idle", id="status")
            with Vertical(id="workspace"):
                with TabbedContent(id="tabs"):
                    with TabPane("Overview", id="tab-overview"):
                        yield Static(id="overview")
                    with TabPane("Findings", id="tab-findings"):
                        yield DataTable(id="findings_table")
                    with TabPane("URLs", id="tab-urls"):
                        yield ListView(id="url_list")
                    with TabPane("Entitlements", id="tab-entitlements"):
                        yield DataTable(id="entitlements_table")
                    with TabPane("Frameworks", id="tab-frameworks"):
                        yield ListView(id="framework_list")
                    with TabPane("Strings", id="tab-strings"):
                        yield VerticalScroll(Static(id="strings_view"))
                    with TabPane("Log", id="tab-log"):
                        yield RichLog(id="log", wrap=True, markup=True)
        yield Footer()

    def on_mount(self) -> None:
        self.query_one("#target_input", Input).focus()
        findings = self.query_one("#findings_table", DataTable)
        findings.add_columns("Severity", "Category", "Title", "Detail")
        entitlements = self.query_one("#entitlements_table", DataTable)
        entitlements.add_columns("Key", "Value")
        self._bundle = None
        self._analysis: AnalysisResult | None = None
        self._report_paths: tuple[Path, Path] | None = None

    def on_button_pressed(self, event: Button.Pressed) -> None:
        btn_id = event.button.id
        if btn_id == "load_btn":
            self._start_load()
        elif btn_id == "download_btn":
            self._start_download()
        elif btn_id == "analyze_btn":
            self._start_analyze()
        elif btn_id == "report_btn":
            self._open_report()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self._start_load()

    def _log(self, message: str) -> None:
        self.query_one("#log", RichLog).write(message)

    def _set_status(self, text: str) -> None:
        self.query_one("#status", Static).update(f"Status: {text}")

    def _set_busy(self, busy: bool) -> None:
        for btn_id in ("load_btn", "download_btn", "analyze_btn", "report_btn"):
            self.query_one(f"#{btn_id}", Button).disabled = busy

    def _start_load(self) -> None:
        target = self.query_one("#target_input", Input).value.strip()
        if not target:
            self._log("[bold red]Enter an IPA path or bundle id first.[/]")
            return
        path = Path(target).expanduser()
        if path.exists() and path.suffix.lower() == ".ipa":
            self._run_load_ipa(path)
        else:
            self.notify("Use Download for bundle ids", title="Invalid load target", severity="warning")

    def _start_download(self) -> None:
        target = self.query_one("#target_input", Input).value.strip()
        if not target:
            self._log("[bold red]Enter a bundle id first.[/]")
            return
        apple_id = self.query_one("#apple_id_input", Input).value.strip()
        password = self.query_one("#apple_password_input", Input).value.strip()
        credentials = None
        if apple_id and password:
            credentials = StoreCredentials(apple_id, password)
        self._run_download(target, credentials)

    def _start_analyze(self) -> None:
        if self._bundle is None:
            self.notify("Load or download an IPA first", severity="warning")
            return
        self._run_analyze(self._bundle)

    def _open_report(self) -> None:
        if self._report_paths is None:
            self.notify("Run analysis first", severity="warning")
            return
        md_path, _ = self._report_paths
        self._log(f"[bold green]Report:[/] {md_path}")

    @work(thread=True, exclusive=True)
    def _run_load_ipa(self, path: Path) -> None:
        self.call_from_thread(self._set_busy, True)
        self.call_from_thread(self._set_status, "loading IPA")
        self.call_from_thread(self._log, f"[cyan]•[/] Loading {path}")
        try:
            from nullios.ipa import IpaBundle
            bundle = IpaBundle.load(path)
            self._bundle = bundle
            self.call_from_thread(self._render_overview)
            self.call_from_thread(
                self.notify,
                f"Loaded {bundle.bundle_id}",
                title="IPA loaded",
                severity="information",
            )
        except NulliosError as exc:
            self.call_from_thread(self._log, f"[bold red]Error:[/] {exc}")
            self.call_from_thread(self.notify, str(exc), title="Load failed", severity="error")
        finally:
            self.call_from_thread(self._set_busy, False)
            self.call_from_thread(self._set_status, "idle")

    @work(thread=True, exclusive=True)
    def _run_download(self, bundle_id: str, credentials: StoreCredentials | None) -> None:
        self.call_from_thread(self._set_busy, True)
        self.call_from_thread(self._set_status, "downloading")
        self.call_from_thread(self._log, f"[cyan]•[/] Downloading {bundle_id}")

        def on_progress(update: pipeline.StepUpdate) -> None:
            self.call_from_thread(self._log, f"[cyan]•[/] {update.message}")

        try:
            md_path, json_path = pipeline.run_store(bundle_id, credentials=credentials, on_progress=on_progress)
            self._report_paths = (md_path, json_path)
            self.call_from_thread(self._log, f"[bold green]Done.[/] {md_path}")
            self.call_from_thread(
                self.notify,
                str(md_path),
                title="Download complete",
                severity="information",
            )
        except NulliosError as exc:
            self.call_from_thread(self._log, f"[bold red]Error:[/] {exc}")
            self.call_from_thread(self.notify, str(exc), title="Download failed", severity="error")
        finally:
            self.call_from_thread(self._set_busy, False)
            self.call_from_thread(self._set_status, "idle")

    @work(thread=True, exclusive=True)
    def _run_analyze(self, bundle) -> None:
        self.call_from_thread(self._set_busy, True)
        self.call_from_thread(self._set_status, "analyzing")

        def on_progress(msg: str) -> None:
            self.call_from_thread(self._log, f"[cyan]•[/] {msg}")

        try:
            result = analyzer.analyze(bundle, on_progress=on_progress)
            self._analysis = result
            self._report_paths = pipeline.report.write_reports(
                result, pipeline.DEFAULT_OUTPUT_DIR
            )
            self.call_from_thread(self._render_results)
            self.call_from_thread(
                self.notify,
                f"{len(result.findings)} findings",
                title="Analysis complete",
                severity="information",
            )
        except NulliosError as exc:
            self.call_from_thread(self._log, f"[bold red]Error:[/] {exc}")
            self.call_from_thread(self.notify, str(exc), title="Analysis failed", severity="error")
        finally:
            self.call_from_thread(self._set_busy, False)
            self.call_from_thread(self._set_status, "idle")

    def _render_overview(self) -> None:
        if self._bundle is None:
            return
        overview = self.query_one("#overview", Static)
        binary = self._bundle.binary
        text = (
            f"[b]Bundle ID:[/] {self._bundle.bundle_id}\n"
            f"[b]Name:[/] {self._bundle.display_name}\n"
            f"[b]Version:[/] {self._bundle.version}\n"
            f"[b]App Dir:[/] {self._bundle.app_dir.name}\n"
            f"[b]Binary:[/] {binary.path.name if binary else 'N/A'}\n"
        )
        overview.update(text)

    def on_unmount(self) -> None:
        if self._bundle is not None:
            self._bundle.cleanup()

    def _render_results(self) -> None:
        if self._analysis is None:
            return
        self._render_overview()

        overview = self.query_one("#overview", Static)
        analysis = self._analysis
        overview.update(
            f"[b]Bundle ID:[/] {analysis.bundle_id}\n"
            f"[b]Name:[/] {analysis.display_name}\n"
            f"[b]Version:[/] {analysis.version}\n"
            f"[b]Platform:[/] {analysis.platform}\n"
            f"[b]Min iOS:[/] {analysis.min_ios}\n"
            f"[b]Architectures:[/] {', '.join(analysis.architectures)}\n"
            f"[b]Encrypted:[/] {analysis.encrypted}\n"
            f"[b]PIE:[/] {analysis.pie}\n"
            f"[b]Stack Canary:[/] {analysis.stack_canary}\n"
            f"[b]ARC:[/] {analysis.arc}\n"
        )

        findings_table = self.query_one("#findings_table", DataTable)
        findings_table.clear()
        for finding in analysis.findings:
            findings_table.add_row(
                finding.severity,
                finding.category,
                finding.title,
                finding.detail,
            )

        url_list = self.query_one("#url_list", ListView)
        url_list.clear()
        for scheme in analysis.url_schemes:
            url_list.append(ListItem(Label(f"{scheme}://")))
        for domain in analysis.universal_links:
            url_list.append(ListItem(Label(domain)))

        entitlements_table = self.query_one("#entitlements_table", DataTable)
        entitlements_table.clear()
        for key, value in analysis.entitlements.items():
            entitlements_table.add_row(str(key), str(value))

        framework_list = self.query_one("#framework_list", ListView)
        framework_list.clear()
        for fw in analysis.frameworks:
            framework_list.append(ListItem(Label(fw)))

        strings_view = self.query_one("#strings_view", Static)
        strings_view.update("\n".join(analysis.interesting_strings[:200]) or "No interesting strings found.")
        strings_view = self.query_one("#strings_view", Static)
        strings_view.update("\n".join(analysis.interesting_strings[:200]) or "No interesting strings found.")


def run() -> None:
    NulliosApp().run()
