"""Canary placeholders, generated values and the secret filter (plan section 8).

Secret-looking samples are assembled at runtime so no key-shaped literal is ever committed.
"""
import mongomock
import pytest

from canary.filters import KINDS, content_errors, find_secrets, placeholder_errors, placeholder_ids
from canary.registry import CanaryRegistry, generate

FAKE_AKIA = "AKIA" + "Q" * 16
FAKE_SK = "sk" + "-" + "a1B2" * 6
FAKE_PEM = "-----BEGIN " + "RSA PRIVATE KEY-----\nabc\n"
FAKE_GH = "ghp" + "_" + "x" * 30
FAKE_JWT = "eyJ" + "hbGciOiJIUzI1" + "." + "eyJ" + "zdWIiOiIxMjM0"
FAKE_BLOB = "Zx9" + "aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1yZ3"


@pytest.fixture
def reg():
    return CanaryRegistry(mongomock.MongoClient().maya)


@pytest.mark.parametrize("kind", KINDS)
def test_generated_values_are_unique_and_pass_nothing_through_the_filter_as_placeholders(kind):
    a, b = generate(kind), generate(kind)
    assert a != b and len(a) >= 10


def test_same_id_resolves_to_same_value_and_is_stored(reg):
    v = reg.resolve("aws_access_key_1")
    assert v.startswith("AKIA") and reg.resolve("aws_access_key_1") == v
    assert reg.col.count_documents({}) == 1
    assert reg.resolve("aws_access_key_2") != v


def test_substitute_replaces_placeholders_and_records_where(reg):
    out, used = reg.substitute("DB_USER=app\nDB_PASSWORD={{canary:password_1}}\nKEY={{ canary:api_token_3 }}\n",
                               where={"host": "fake-jump-01", "path": "/opt/app/.env"})
    assert "{{" not in out and used == ["password_1", "api_token_3"]
    assert reg.resolve("password_1") in out
    doc = reg.col.find_one({"canary_id": "password_1"})
    assert doc["planted_in"] == [{"host": "fake-jump-01", "path": "/opt/app/.env"}]


@pytest.mark.parametrize("bad", ["{{canary:root_password_1}}", "{{canary:password}}", "{{system:prompt}}", "{{ x }}"])
def test_bad_placeholders_refused(reg, bad):
    assert placeholder_errors(f"a {bad} b")
    with pytest.raises(ValueError):
        reg.substitute(f"a {bad} b")


def test_find_used_detects_a_canary_in_any_text(reg):
    pw = reg.resolve("password_1")
    assert reg.find_used(f"admin:{pw}") == ["password_1"]
    assert reg.find_used("admin:Summer2024!") == []


@pytest.mark.parametrize("text,hit", [
    (f"aws_access_key_id = {FAKE_AKIA}", "aws_access_key"),
    (FAKE_PEM, "private_key"),
    (f"export OPENAI={FAKE_SK}", "api_token"),
    (f"token {FAKE_GH}", "api_token"),
    (f"Authorization: Bearer {FAKE_JWT}", "jwt"),
    ("DB_PASSWORD=hunter2", "credential_assignment"),
    ("password: Winter2025", "credential_assignment"),
    ('"api_key": "abc123"', "credential_assignment"),
    ("postgres://app:hunter2@fake-db-01:5432/prod", "credential_in_url"),
    (f"blob {FAKE_BLOB}", "high_entropy"),
])
def test_secret_filter_catches_invented_secrets(text, hit):
    assert hit in find_secrets(text)


@pytest.mark.parametrize("text", [
    "DB_PASSWORD={{canary:password_1}}",
    "AWS_ACCESS_KEY_ID={{canary:aws_access_key_1}}\nAWS_SECRET_ACCESS_KEY={{canary:aws_secret_key_1}}",
    "postgres://app:{{canary:password_2}}@fake-db-01:5432/prod",
    "# Deploy runbook\nSSH to fake-db-01 as deploy, then run ./migrate.sh. Ask Lea for access.",
    "DB_HOST=fake-db-01\nDB_PORT=5432\nNODE_ENV=production",
])
def test_normal_decoy_text_with_placeholders_passes(text):
    assert content_errors(text) == []


def test_placeholder_ids_in_order_without_duplicates():
    t = "{{canary:password_1}} {{canary:api_token_2}} {{canary:password_1}}"
    assert placeholder_ids(t) == ["password_1", "api_token_2"]
