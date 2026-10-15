# cipherAudit

Command-line TLS configuration scanner. It probes a server with its own raw handshake layer (so old
protocols and ciphers are testable regardless of the local OpenSSL), then explains each finding in plain
language with a NIST reference, a fix and a 0-100 score. See `PRD.md` and `TRD.md`.

Only scan systems you own or have written permission to test.

## Setup

```
uv venv --python 3.13
uv pip install -e ".[dev]"
```

## Usage

```
cipheraudit scan example.com
cipheraudit scan example.com:8443 --json report.json --html report.html -v
cipheraudit scan host --i-have-permission --no-active-vulns      # scripted, derived checks only
cipheraudit scan host --protocols                                # protocol probing only
```

Exit codes: 0 scan completed, 1 scan error, 2 not authorized, 3 target unreachable.

## Development

```
pytest                                                    # unit tests, no network
docker compose -f tests/targets/docker-compose.yml up -d --build
docker cp targets-modern-1:/etc/nginx/certs/ca.pem tests/targets/certs/modern-ca.pem
pytest -m network                                         # integration tests against local targets
ruff check src tests tools && mypy src
python tools/build_data.py <dir>                          # regenerate ciphers.json / groups.json from IANA
```

Accuracy check against testssl.sh: see `tests/compare_testssl.py`.
