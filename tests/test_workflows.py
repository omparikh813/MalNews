import re

import pytest
import yaml

from .conftest import ROOT

WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
SHA_PIN = re.compile(r"^[\w.-]+/[\w.-]+(/[\w./-]+)?@[0-9a-f]{40}$")


def load(name):
    return yaml.safe_load((ROOT / ".github" / "workflows" / name).read_text())


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_every_action_is_pinned_to_a_commit(path):
    wf = yaml.safe_load(path.read_text())
    uses = [s["uses"] for job in wf["jobs"].values() for s in job["steps"] if "uses" in s]
    assert uses and all(SHA_PIN.match(u) for u in uses), uses


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_token_is_read_only_by_default(path):
    assert yaml.safe_load(path.read_text())["permissions"] == {"contents": "read"}


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_checkouts_do_not_keep_the_token(path):
    for job in yaml.safe_load(path.read_text())["jobs"].values():
        for step in job["steps"]:
            if step.get("uses", "").startswith("actions/checkout@"):
                assert step["with"]["persist-credentials"] is False


def test_only_the_build_job_sees_the_api_keys():
    jobs = load("daily.yml")["jobs"]
    holders = {name for name, job in jobs.items() if re.search(r"secrets\.(OPENROUTER|NVD)", yaml.dump(job))}
    assert holders == {"build"}
    assert "permissions" not in jobs["build"]


def test_write_access_is_limited_to_the_jobs_that_need_it():
    jobs = load("daily.yml")["jobs"]
    assert jobs["deploy"]["permissions"] == {"pages": "write", "id-token": "write"}
    assert jobs["data"]["permissions"] == {"contents": "write"}
    assert load("keepalive.yml")["jobs"]["keepalive"]["permissions"] == {"contents": "write"}


def test_deploy_only_on_schedule_or_when_asked():
    wf = load("daily.yml")
    assert wf["jobs"]["deploy"]["if"] == "github.event_name == 'schedule' || inputs.deploy"
    assert wf[True]["workflow_dispatch"]["inputs"]["deploy"]["default"] is False
    assert wf["jobs"]["data"]["needs"] == ["build", "deploy"]


def test_daily_schedule_and_python_version():
    wf = load("daily.yml")
    assert wf[True]["schedule"] == [{"cron": "0 14 * * *"}]
    setup = next(s for s in wf["jobs"]["build"]["steps"] if s.get("uses", "").startswith("actions/setup-python@"))
    assert setup["with"]["python-version"] == "3.12"


def test_run_steps_do_not_interpolate_github_context():
    for path in WORKFLOWS:
        for job in yaml.safe_load(path.read_text())["jobs"].values():
            for step in job["steps"]:
                assert "${{" not in step.get("run", ""), step["run"]
