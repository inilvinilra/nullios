import json
from dataclasses import asdict
from pathlib import Path

from nullios.analyzer import AnalysisResult


REPORT_BANNER = """# nullios Analysis Report

| Field | Value |
|-------|-------|
| Bundle ID | {bundle_id} |
| Display Name | {display_name} |
| Version | {version} |
| Platform | {platform} |
| Min iOS | {min_ios} |
| Architectures | {architectures} |
| Encrypted | {encrypted} |
| PIE | {pie} |
| Stack Canary | {stack_canary} |
| ARC | {arc} |

## Findings

{findings}

## URL Schemes

{url_schemes}

## Universal Links / Associated Domains

{universal_links}

## App Transport Security

{ats}

## Entitlements

```json
{entitlements}
```

## Permissions

{permissions}

## Frameworks

{frameworks}

## Interesting Strings ({interesting_count})

{interesting_strings}
"""


def _fmt_list(items: list[str]) -> str:
    if not items:
        return "None"
    return "\n".join(f"- {item}" for item in items)


def _fmt_findings(result: AnalysisResult) -> str:
    if not result.findings:
        return "No findings."
    lines = []
    for finding in result.findings:
        lines.append(f"- **[{finding.severity.upper()}] {finding.title}** ({finding.category})\n  - {finding.detail}")
    return "\n".join(lines)


def generate_markdown(result: AnalysisResult) -> str:
    return REPORT_BANNER.format(
        bundle_id=result.bundle_id or "N/A",
        display_name=result.display_name or "N/A",
        version=result.version or "N/A",
        platform=result.platform or "N/A",
        min_ios=result.min_ios or "N/A",
        architectures=", ".join(result.architectures) or "N/A",
        encrypted=result.encrypted,
        pie=result.pie,
        stack_canary=result.stack_canary,
        arc=result.arc,
        findings=_fmt_findings(result),
        url_schemes=_fmt_list(result.url_schemes),
        universal_links=_fmt_list(result.universal_links),
        ats="\n".join(result.ats_details) if result.ats_details else "ATS restrictions enforced",
        entitlements=json.dumps(result.entitlements, indent=2, default=str),
        permissions=_fmt_list(result.permissions),
        frameworks=_fmt_list(result.frameworks),
        interesting_count=len(result.interesting_strings),
        interesting_strings=_fmt_list(result.interesting_strings),
    )


def generate_json(result: AnalysisResult) -> str:
    return json.dumps(asdict(result), indent=2, default=str)


def write_reports(result: AnalysisResult, output_dir: Path) -> tuple[Path, Path]:
    output_dir = Path(output_dir).expanduser()
    output_dir.mkdir(parents=True, exist_ok=True)
    safe_name = (result.bundle_id or "unknown").replace(".", "_")
    md_path = output_dir / f"{safe_name}.md"
    json_path = output_dir / f"{safe_name}.json"
    md_path.write_text(generate_markdown(result), encoding="utf-8")
    json_path.write_text(generate_json(result), encoding="utf-8")
    return md_path, json_path
