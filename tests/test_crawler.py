"""Reactive crawler: extraction, and a full run against a lab built from a real rendered environment."""
import json
from pathlib import Path

import mongomock
import pytest

from attackers.crawler import CrawlConfig, Crawler
from attackers.extract import extract
from builder.render import RenderConfig, render_environment
from builder.spec import EnvironmentSpec
from canary.registry import CanaryRegistry
from test_render import spec_dict


# ---------------------------------------------------------------- extraction
def test_extract_env_file_gives_host_user_password():
    leads = extract("NODE_ENV=production\nDB_HOST=pay-db-02\nDB_USER=payouts\nDB_PASSWORD=Harbor4821!xy\n")
    assert ("pay-db-02", "payouts", "Harbor4821!xy") in leads.host_creds and "pay-db-02" in leads.hosts


def test_extract_connection_uri():
    leads = extract("postgres://app:S3cretWord@pay-db-02:5432/prod")
    assert ("pay-db-02", "app", "S3cretWord") in leads.host_creds


def test_extract_note_and_ssh():
    leads = extract("DB server pay-db-02\n  user: payouts\n  pass: Maple7731$ab\nthen: ssh payouts@pay-db-02")
    assert "pay-db-02" in leads.hosts
    assert any(u == "payouts" and p == "Maple7731$ab" for _, u, p in leads.host_creds) or \
           ("payouts", "Maple7731$ab") in leads.creds


def test_extract_urls_and_paths():
    leads = extract("see http://wiki/database-migration-runbook and /opt/app/.env and /var/backups/dump.sql")
    assert "http://wiki/database-migration-runbook" in leads.urls
    assert "/opt/app/.env" in leads.paths and "/var/backups/dump.sql" in leads.paths


def test_extract_ignores_noise_words():
    assert extract("production environment, password required, see readme").hosts == set()


# ---------------------------------------------------------------- a lab from a real rendered environment
class LabSession:
    def __init__(self, lab, host, user):
        self.lab, self.host, self.user = lab, host, user

    def run(self, command):
        return self.lab.run(self.host, self.user, command)

    def close(self):
        pass


class FakeLab:
    """Serves exactly what builder/render.py wrote: real hostnames, userdb passwords, honeyfs file contents."""

    def __init__(self, deception, render, world):
        self.files, self.logins, self.slot_of = {}, {}, {}
        for h in world["hosts"]:
            slot, hostname = h["slot"], h["hostname"]
            self.slot_of[hostname] = slot
            udb = Path(render) / slot / "etc" / "userdb.txt"
            self.logins[hostname] = {}
            for line in udb.read_text().splitlines():
                if line and not line.startswith("#"):
                    u, _, p = line.split(":x:")[0], None, line.split(":x:")[1]
                    self.logins[hostname][line.split(":x:")[0]] = line.split(":x:")[1]
            self.files[hostname] = {}
            base = Path(deception) / slot
            for f in base.rglob("*"):
                if f.is_file():
                    self.files[hostname]["/" + f.relative_to(base).as_posix()] = f.read_text(errors="replace")
        self.connections = []

    def connect(self, host, port, user, password):
        self.connections.append((host, user, password))
        if self.logins.get(host, {}).get(user) == password:
            return LabSession(self, host, user)
        return None

    def run(self, host, user, command):
        files = self.files[host]
        home = "/root" if user == "root" else f"/home/{user}"
        cmd = command.replace("~", home)
        if cmd.startswith("whoami"):
            return user + "\n"
        if cmd.startswith("hostname"):
            return host + "\n"
        if cmd.startswith("find "):
            roots = [t for t in cmd.split() if t.startswith("/")]
            return "".join(p + "\n" for p in files if any(p == r or p.startswith(r + "/") for r in roots))
        if cmd.startswith("cat "):
            return files.get(cmd[4:].strip(), "cat: no such file\n")
        if cmd.startswith("ls"):
            return "\n".join(sorted(files)) + "\n"
        return ""


@pytest.fixture
def lab(tmp_path):
    db = mongomock.MongoClient().maya
    reg = CanaryRegistry(db)
    cfg = RenderConfig(deception_dir=tmp_path / "deception", render_dir=tmp_path / "render")
    render_environment(EnvironmentSpec.model_validate(spec_dict()), reg, cfg, "env-1", db)
    world = json.loads((cfg.render_dir / "world_model.json").read_text())
    entry_pw = [l.split(":x:")[1] for l in (cfg.render_dir / "fake-jump-01" / "etc" / "userdb.txt").read_text()
                .splitlines() if l and not l.startswith("#")][0]
    return FakeLab(cfg.deception_dir, cfg.render_dir, world), entry_pw, reg


def test_crawler_follows_the_env_breadcrumb_into_the_database_decoy(lab):
    fake, entry_pw, reg = lab
    cfg = CrawlConfig("pay-jump-01", "deploy", entry_pw, decoy_hosts=("pay-jump-01", "pay-db-02", "pay-files-01"))
    res = Crawler(cfg, fake, run_id="r-0007").run()
    assert res.entered_hosts[0] == "pay-jump-01"
    assert "pay-db-02" in res.entered_hosts                 # read the .env, reused the canary password, pivoted
    db_pw = reg.resolve("password_1")
    assert ("pay-db-02", "payouts", db_pw) in fake.connections
    assert res.commands <= cfg.max_commands


def test_crawler_reads_the_planted_db_dump_on_the_second_host(lab):
    fake, entry_pw, _ = lab
    res = Crawler(CrawlConfig("pay-jump-01", "deploy", entry_pw,
                              decoy_hosts=("pay-jump-01", "pay-db-02", "pay-files-01")), fake).run()
    read = [s.command for s in res.steps if s.host == "pay-db-02" and s.command.startswith("cat")]
    assert any("customers.sql" in c for c in read)


def test_crawler_is_reproducible_for_a_seed(lab):
    fake, pw, _ = lab
    a = Crawler(CrawlConfig("pay-jump-01", "deploy", pw, seed=5), fake).run()
    b = Crawler(CrawlConfig("pay-jump-01", "deploy", pw, seed=5), fake).run()
    assert [(s.host, s.command) for s in a.steps] == [(s.host, s.command) for s in b.steps]


def test_crawler_respects_the_command_budget(lab):
    fake, pw, _ = lab
    res = Crawler(CrawlConfig("pay-jump-01", "deploy", pw, max_commands=8), fake).run()
    assert res.commands <= 8


def test_crawler_never_contacts_a_non_decoy_host(lab):
    fake, pw, _ = lab
    Crawler(CrawlConfig("pay-jump-01", "deploy", pw, decoy_hosts=("pay-jump-01",)), fake).run()
    assert {h for h, _, _ in fake.connections} <= {"pay-jump-01"}


def test_wrong_entry_password_gets_nowhere(lab):
    fake, _, _ = lab
    res = Crawler(CrawlConfig("pay-jump-01", "deploy", "not-the-password"), fake).run()
    assert res.entered_hosts == [] and res.commands == 0


def test_crawler_fetches_wiki_urls_it_finds():
    pages = {"http://wiki/db-runbook": (200, "ssh payouts@pay-db-02 then check /var/backups")}
    fetched = []

    class OneHost:
        def connect(self, host, port, user, password):
            return self if (host, user, password) == ("jump", "deploy", "pw") else None

        def run(self, command):
            return "see http://wiki/db-runbook for the migration steps" if command.startswith("cat ~") else ""

        def close(self):
            pass

    def http_get(url):
        fetched.append(url)
        return pages.get(url, (404, ""))

    res = Crawler(CrawlConfig("jump", "deploy", "pw", wiki_base="http://wiki"), OneHost(), http_get).run()
    assert "http://wiki/db-runbook" in fetched and "http://wiki/db-runbook" in res.urls_fetched


def test_groundtruth_matches_schema(lab):
    fake, pw, _ = lab
    res = Crawler(CrawlConfig("pay-jump-01", "deploy", pw), fake).run()
    gt = res.to_groundtruth()
    schema = json.loads((Path(__file__).resolve().parents[1] / "schemas" / "groundtruth.json").read_text())
    from jsonschema import Draft202012Validator
    assert list(Draft202012Validator(schema).iter_errors(gt)) == []
    assert gt["persona"] == "crawler" and gt["steps"]
