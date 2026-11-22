"""Repository hygiene: no real-looking secrets, example tokens are obviously fake, third-party licences listed."""
import math, os, re
from collections import Counter

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SKIP_DIRS = {"results", "artifacts", "data", "logs", "venv", ".venv", ".git", "__pycache__", "node_modules",
             ".pytest_cache", ".hypothesis", "evidence"}
EXTS = {".py", ".sh", ".yml", ".yaml", ".toml", ".ini", ".cfg", ".service", ".conf", ".json", ".md", ".txt",
        ".html", ".js"}
KNOWN = [
    (r"AKIA[0-9A-Z]{16}", "AWS access key"),
    (r"gh[pousr]_[A-Za-z0-9]{36,}", "GitHub token"),
    (r"github_pat_[A-Za-z0-9_]{40,}", "GitHub PAT"),
    (r"\bsk-[A-Za-z0-9_\-]{32,}", "API secret key"),
    (r"\bhf_[A-Za-z0-9]{30,}", "Hugging Face token"),
    (r"xox[abprs]-[A-Za-z0-9\-]{10,}", "Slack token"),
    (r"AIza[0-9A-Za-z_\-]{35}", "Google API key"),
    (r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----", "private key"),
]
TOKEN = re.compile(r"[A-Za-z0-9+_\-=]{24,}")
SECRET_VAR = re.compile(r"(TOKEN|SECRET|PASSW|API_?KEY|PRIVATE)", re.I)


def entropy(s):
    c, n = Counter(s), len(s)
    return -sum(v / n * math.log2(v / n) for v in c.values())


def source_files():
    for dp, dns, fns in os.walk(ROOT):
        dns[:] = [d for d in dns if d not in SKIP_DIRS]
        for fn in fns:
            ext = os.path.splitext(fn)[1]
            if ext in EXTS or fn.startswith(".env"):
                p = os.path.join(dp, fn)
                if os.path.getsize(p) < 2_000_000:
                    yield p


def looks_secret(tok):
    if "example" in tok.lower() or "not_a" in tok.lower() or "not-a" in tok.lower():
        return False
    return (entropy(tok) >= 4.5 and re.search(r"[a-z]", tok) and re.search(r"[A-Z]", tok)
            and re.search(r"\d", tok))


def test_no_real_looking_secrets_in_repo():
    hits = []
    for p in source_files():
        rel = os.path.relpath(p, ROOT)
        for i, line in enumerate(open(p, errors="ignore"), 1):
            for pat, what in KNOWN:
                if re.search(pat, line):
                    hits.append("%s:%d %s" % (rel, i, what))
            for tok in TOKEN.findall(re.sub(r"https?://\S+", " ", line)):     # URL paths are not secrets
                if looks_secret(tok):
                    hits.append("%s:%d high-entropy %r" % (rel, i, tok[:12] + "..."))
    assert hits == [], "possible secrets:\n" + "\n".join(hits)


def test_scanner_detects_a_planted_secret():
    """the scanner itself works (the planted value is assembled at runtime, never stored in the repo)"""
    import random, string
    r = random.Random(3)
    alphabet = string.ascii_letters + string.digits
    planted = "".join(r.choice(alphabet) for _ in range(40))
    assert looks_secret(planted)
    assert not looks_secret("EXAMPLE-NOT-A-SECRET-0000")


def env_example():
    p = os.path.join(ROOT, ".env.example")
    assert os.path.exists(p), ".env.example missing"
    out = {}
    for line in open(p):
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip().strip('"\'')
    return out


def test_env_example_tokens_are_placeholders():
    env = env_example()
    secrets = {k: v for k, v in env.items() if SECRET_VAR.search(k)}
    assert secrets, "no token placeholder in .env.example"
    for k, v in secrets.items():
        assert "example" in v.lower(), "%s does not look like a placeholder" % k
        assert not looks_secret(v)


def test_env_example_has_halo_api_token_with_EXAMPLE():
    env = env_example()
    assert "HALO_API_TOKEN" in env, "halo/api.py reads HALO_API_TOKEN; document it in .env.example"
    assert "EXAMPLE" in env["HALO_API_TOKEN"]


def test_api_reads_token_from_env_not_source():
    src = open(os.path.join(ROOT, "halo", "api.py")).read()
    assert 'os.environ.get("HALO_API_TOKEN"' in src
    assert "EXAMPLE-NOT-A-SECRET" not in src


def test_real_env_file_not_committed_and_ignored():
    gi = open(os.path.join(ROOT, ".gitignore")).read().split()
    assert ".env" in gi


@pytest.mark.parametrize("component", [
    ("tc", "iproute2"), ("nftables",), ("XGBoost",), ("scikit-learn",), ("FastAPI",),
    ("Prometheus",), ("Grafana",), ("iperf3",), ("irtt",),
])
def test_third_party_licenses_listed(component):
    p = os.path.join(ROOT, "THIRD_PARTY_LICENSES.md")
    assert os.path.exists(p)
    text = open(p).read().lower()
    for name in component:
        assert name.lower() in text, "%s missing from THIRD_PARTY_LICENSES.md" % name


def test_third_party_licenses_have_licence_column():
    rows = [l for l in open(os.path.join(ROOT, "THIRD_PARTY_LICENSES.md")) if l.startswith("|") and "---" not in l][1:]
    assert rows
    for r in rows:
        cells = [c.strip() for c in r.strip().strip("|").split("|")]
        assert len(cells) >= 2 and cells[1], r


FALLBACK = re.compile(r"environ\.get\(\s*['\"][A-Z0-9_]*(TOKEN|SECRET|PASSW|API_?KEY)[A-Z0-9_]*['\"]\s*"
                      r"(?:,\s*['\"][^'\"]+['\"]\s*\)|\)\s*or\s*['\"][^'\"]+['\"])")


def test_no_hard_coded_credential_fallbacks():
    """`os.environ.get("X_TOKEN") or "literal"` / `.get("X_TOKEN", "literal")` silently ship a credential"""
    hits = []
    for p in source_files():
        if p.endswith(".py") and "tests_halo" not in p:
            for i, line in enumerate(open(p, errors="ignore"), 1):
                if FALLBACK.search(line):
                    hits.append("%s:%d %s" % (os.path.relpath(p, ROOT), i, line.strip()))
    assert hits == [], "\n".join(hits)
    assert FALLBACK.search('t = os.environ.get("AQE_API_TOKEN") or "demo-token"')
    assert FALLBACK.search('t = os.environ.get("HALO_API_TOKEN", "abc")')
    assert not FALLBACK.search('TOKEN = os.environ.get("HALO_API_TOKEN", "")')


def test_full_demo_reads_halo_token_and_fails_when_unset():
    src = open(os.path.join(ROOT, "scripts", "run_full_demo.py")).read()
    assert 'os.environ.get("HALO_API_TOKEN")' in src
    assert "aqe-authoritative-demo-token" not in src
    assert re.search(r"if not demo_token:\s*\n\s*sys\.exit\(", src)
