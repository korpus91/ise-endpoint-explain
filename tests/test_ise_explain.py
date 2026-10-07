import shutil
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
FX = HERE / "fixtures"
sys.path.insert(0, str(HERE.parent))
import ise_explain as ie  # noqa: E402


def records():
    return ie.parse_authstatus((FX / "authstatus.xml").read_text())


def test_records_parsed_and_sorted_newest_first():
    r = records()
    assert len(r) == 3
    assert r[0]["acs_timestamp"].startswith("2026-10-06 14:22")
    assert ie.passed(r[0]) and not ie.passed(r[1])


def test_matched_rule_comes_from_other_attr_string():
    assert ie.first(records()[0], "AuthorizationPolicyMatchedRule") == "Corp-EAP-TLS"


@pytest.mark.parametrize("reason,needle", [
    ("12514 EAP-TLS failed ... unknown CA", "unknown CA"),
    ("11036 The Message-Authenticator RADIUS attribute is invalid", "shared secret"),
    ("99999 something new", ""),
])
def test_failure_hints(reason, needle):
    h = ie.hint(reason)
    assert (needle in h) if needle else h == ""


@pytest.mark.parametrize("raw", ["aa:bb:cc:00:11:22", "AA-BB-CC-00-11-22", "aabb.cc00.1122"])
def test_mac_normalization(raw):
    assert ie.normalize_mac(raw) == "AA:BB:CC:00:11:22"


def test_render_contains_session_and_reasons():
    out = ie.render("AA:BB:CC:00:11:22", ie.parse_session((FX / "session.xml").read_text()), records())
    assert "192.0.2.55" in out and "Corp-Access" in out and "likely cause" in out


def test_cli_exit_codes(tmp_path, capsys):
    assert ie.main(["aa:bb:cc:00:11:22", "--offline", str(FX)]) == 0
    # newest record failing -> exit 1, and a missing session.xml is tolerated
    d = tmp_path / "f"
    d.mkdir()
    text = (FX / "authstatus.xml").read_text().replace("2026-10-05 17:40", "2026-10-07 09:00")
    (d / "authstatus.xml").write_text(text)
    assert ie.main(["aa:bb:cc:00:11:22", "--offline", str(d)]) == 1
    assert "none" in capsys.readouterr().out
    assert ie.main(["not-a-mac", "--offline", str(FX)]) == 2