from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from cloudsecurity_af.agents.recon.iac_reader import run_iac_reader
from cloudsecurity_af.schemas.recon import ResourceInventory


def _make_repo_with_tf(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "main.tf").write_text('resource "aws_s3_bucket" "b" {}')
    return repo


def _make_repo_without_tf(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "template.yaml").write_text("AWSTemplateFormatVersion: '2010-09-09'")
    return repo


def _mock_app_with_harness_result(inventory_path: str, total: int = 3) -> AsyncMock:
    app = AsyncMock()
    mock_result = MagicMock()
    mock_result.is_error = False
    mock_result.parsed = ResourceInventory(
        inventory_saved_path=inventory_path,
        total_resources=total,
        iac_type="cloudformation",
    )
    app.harness.return_value = mock_result
    return app


class TestIacReaderRouting:
    @pytest.mark.asyncio
    async def test_tf_files_present_uses_fast_parse(self, tmp_path: Path) -> None:
        repo = _make_repo_with_tf(tmp_path)
        inv = ResourceInventory(
            inventory_saved_path="/tmp/inv.json",
            total_resources=5,
            iac_type="terraform",
        )
        app = AsyncMock()
        with patch(
            "cloudsecurity_af.agents.recon.iac_reader._fast_parse",
            return_value=inv,
        ) as mock_fast:
            result = await run_iac_reader(app, str(repo))
            mock_fast.assert_called_once()
            app.harness.assert_not_called()
            assert result.iac_type == "terraform"
            assert result.total_resources == 5

    @pytest.mark.asyncio
    async def test_no_tf_files_uses_harness(self, tmp_path: Path) -> None:
        repo = _make_repo_without_tf(tmp_path)
        app = _mock_app_with_harness_result("/tmp/inv.json")
        with patch(
            "cloudsecurity_af.agents.recon.iac_reader._fast_parse",
        ) as mock_fast:
            result = await run_iac_reader(app, str(repo))
            mock_fast.assert_not_called()
            app.harness.assert_called_once()
            assert result.iac_type == "cloudformation"

    @pytest.mark.asyncio
    async def test_fast_parse_failure_falls_through_to_harness(self, tmp_path: Path) -> None:
        repo = _make_repo_with_tf(tmp_path)
        app = _mock_app_with_harness_result("/tmp/inv.json", total=2)
        with patch(
            "cloudsecurity_af.agents.recon.iac_reader._fast_parse",
            side_effect=RuntimeError("pyhcl2 parse error"),
        ):
            result = await run_iac_reader(app, str(repo))
            app.harness.assert_called_once()
            assert result.total_resources == 2

    @pytest.mark.asyncio
    async def test_harness_receives_format_agnostic_prompt(self, tmp_path: Path) -> None:
        repo = _make_repo_without_tf(tmp_path)
        app = _mock_app_with_harness_result("/tmp/inv.json")
        await run_iac_reader(app, str(repo))
        prompt = app.harness.call_args.kwargs.get("prompt", "")
        assert "pyhcl2" not in prompt
        assert "ANY" in prompt or "Kubernetes" in prompt or "CloudFormation" in prompt
