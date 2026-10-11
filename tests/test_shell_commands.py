"""The emulated shell handles the command forms an LLM attacker actually uses."""
import json
from pathlib import Path

import mongomock
import pytest

from builder.render import RenderConfig, render_environment
from builder.spec import EnvironmentSpec
from canary.registry import CanaryRegistry
from honeynet.emulated_shell import EmulatedHoneynet
from test_render import spec_dict


@pytest.fixture
def sh(tmp_path):
    db = mongomock.MongoClient().maya
    reg = CanaryRegistry(db)
    cfg = RenderConfig(deception_dir=tmp_path / "deception", render_dir=tmp_path / "render")
    render_environment(EnvironmentSpec.model_validate(spec_dict()), reg, cfg, "env-1", db)
    world = json.loads((cfg.render_dir / "world_model.json").read_text())
    net = EmulatedHoneynet(cfg.deception_dir, cfg.render_dir, world, tmp_path / "decoys")
    pw = net.decoys["pay-jump-01"].logins["deploy"]
    return net.connect("pay-jump-01", 2222, "deploy", pw), reg


def test_compound_command_runs_every_part(sh):
    s, _ = sh
    out = s.run("whoami && id && hostname && pwd")
    assert "deploy" in out and "uid=1000" in out and "pay-jump-01" in out and "/home/deploy" in out


def test_stderr_redirect_stripped(sh):
    s, _ = sh
    assert "deploy" in s.run("whoami 2>/dev/null")
    assert "NODE_ENV" in s.run("cat /opt/payouts/.env 2>/dev/null || echo missing")


def test_find_with_name_glob(sh):
    s, _ = sh
    out = s.run("find / -type f -name '*.env' 2>/dev/null")
    assert "/opt/payouts/.env" in out and "/etc/passwd" not in out


def test_find_whole_tree_discovers_breadcrumb(sh):
    s, _ = sh
    assert "/opt/payouts/.env" in s.run("find /opt -type f")


def test_cat_reads_canary_value(sh):
    s, reg = sh
    assert reg.resolve("password_1") in s.run("cat /opt/payouts/.env")


def test_pipe_grep_and_head(sh):
    s, _ = sh
    out = s.run("cat /opt/payouts/.env | grep PASSWORD")
    assert "PASSWORD" in out and "NODE_ENV" not in out
    assert len(s.run("find / -type f | head -2").splitlines()) <= 2


def test_ls_directory(sh):
    s, _ = sh
    assert "payouts" in s.run("ls -la /opt")


def test_grep_recursive_over_file(sh):
    s, _ = sh
    assert "DB_PASSWORD" in s.run("grep -i password /opt/payouts/.env")
