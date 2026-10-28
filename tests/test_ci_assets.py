"""CI/CD integration assets are present and point at the real CLI."""
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_github_action_contract():
    action = (ROOT / "action.yml").read_text(encoding="utf-8")
    assert "using: \"composite\"" in action
    assert "jgd" in action and "audit" in action
    assert "sarif-file" in action
    assert "gate-file" in action
    assert "baseline" in action


def test_ci_templates_exist():
    for name in (
        "ci/github-actions.yml",
        "ci/gitlab-ci.yml",
        "ci/Jenkinsfile",
        "ci/pre-commit",
        "ci/README.md",
        ".pre-commit-hooks.yaml",
    ):
        assert (ROOT / name).is_file(), name


def test_ci_templates_use_gate_artifacts():
    gitlab = (ROOT / "ci/gitlab-ci.yml").read_text(encoding="utf-8")
    jenkins = (ROOT / "ci/Jenkinsfile").read_text(encoding="utf-8")
    assert "jgd-report/report.sarif" in gitlab
    assert "jgd-report/report.sarif" in jenkins
    assert "--fail-on" in gitlab
    assert "--fail-on" in jenkins
