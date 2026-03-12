from __future__ import annotations

import logging
import tempfile
from pathlib import Path
from typing import Callable, Protocol

from cloudsecurity_af.agents._utils import extract_harness_result
from cloudsecurity_af.agents.recon._terraform_parser import parse_terraform_directory
from cloudsecurity_af.schemas.recon import ResourceInventory

log = logging.getLogger(__name__)


class HarnessCapable(Protocol):
    async def harness(
        self, prompt: str, *, schema: object = None, cwd: str | None = None, **kwargs: object
    ) -> object: ...


PROMPT_PATH = Path(__file__).resolve().parents[4] / "prompts" / "recon" / "iac_reader.txt"


async def run_iac_reader(app: HarnessCapable, repo_path: str) -> ResourceInventory:
    work_dir = tempfile.mkdtemp(prefix="cloudsecurity-recon-iac-reader-")
    iac_type = _detect_iac_type(repo_path)

    if iac_type == "terraform":
        try:
            return _fast_parse(repo_path, work_dir)
        except Exception as exc:
            log.warning("Terraform fast parse failed (%s), falling back to harness", exc)

    return await _harness_parse(app, repo_path, work_dir, iac_type)


def _fast_parse(repo_path: str, work_dir: str) -> ResourceInventory:
    inv_path, total, iac_type = parse_terraform_directory(repo_path, work_dir)
    return ResourceInventory(
        inventory_saved_path=inv_path,
        total_resources=total,
        iac_type=iac_type,
    )


async def _harness_parse(
    app: HarnessCapable,
    repo_path: str,
    work_dir: str,
    iac_type: str,
) -> ResourceInventory:
    prompt_template = PROMPT_PATH.read_text(encoding="utf-8")
    prompt = prompt_template.replace("{{REPO_PATH}}", repo_path).replace("{{IAC_TYPE}}", iac_type)
    result = await app.harness(
        prompt=prompt,
        schema=ResourceInventory,
        cwd=work_dir,
        project_dir=repo_path,
    )
    return extract_harness_result(result, ResourceInventory, "IaC reader")


def _detect_iac_type(repo_path: str) -> str:
    repo = Path(repo_path)

    if _has_glob(repo, "*.tf"):
        return "terraform"

    if _has_glob(repo, "*.template") or _has_yaml_matching(repo, _looks_like_cloudformation):
        return "cloudformation"

    if _has_glob(repo, "Chart.yaml"):
        return "helm"

    if _has_yaml_matching(repo, _looks_like_kubernetes):
        return "kubernetes"

    if _has_glob(repo, "Pulumi.yaml"):
        return "pulumi"

    if _has_glob(repo, "*.bicep"):
        return "bicep"

    if (
        _has_glob(repo, "Dockerfile")
        or _has_glob(repo, "docker-compose*.yml")
        or _has_glob(repo, "docker-compose*.yaml")
    ):
        return "docker"

    if (
        _has_glob(repo, "*.playbook.yml")
        or _has_glob(repo, "*.playbook.yaml")
        or _has_glob(repo, "site.yml")
        or _has_glob(repo, "site.yaml")
    ):
        return "ansible"

    return "unknown"


def _has_glob(repo: Path, pattern: str) -> bool:
    return next(repo.rglob(pattern), None) is not None


def _has_yaml_matching(repo: Path, predicate: Callable[[Path], bool]) -> bool:
    for pattern in ("*.yaml", "*.yml"):
        for yaml_file in repo.rglob(pattern):
            if predicate(yaml_file):
                return True
    return False


def _looks_like_cloudformation(file_path: Path) -> bool:
    text = _read_small_text(file_path)
    if not text:
        return False

    lowered = text.lower()
    if "awstemplateformatversion" in lowered:
        return True
    if "transform:" in lowered and "aws::" in lowered:
        return True
    return "resources:" in lowered and "type: aws::" in lowered


def _looks_like_kubernetes(file_path: Path) -> bool:
    text = _read_small_text(file_path)
    if not text:
        return False

    lowered = text.lower()
    if "type: aws::" in lowered:
        return False
    return "apiversion:" in lowered and "kind:" in lowered


def _read_small_text(file_path: Path) -> str:
    try:
        return file_path.read_text(encoding="utf-8", errors="ignore")[:16000]
    except OSError:
        return ""
