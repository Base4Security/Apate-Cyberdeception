"""Comprueba el entrypoint HTTP real de la imagen en un puerto local de CI."""

from __future__ import annotations

import argparse
import time
from urllib.error import HTTPError, URLError
from urllib.request import urlopen


def check_service(base_url: str, expected_commit: str, *, timeout_seconds: int = 180) -> dict:
    """Espera el arranque y verifica fuente, login y política de acceso."""
    if not base_url.startswith("http://127.0.0.1:") or not expected_commit:
        raise ValueError("service_smoke_requires_loopback_and_commit")
    deadline = time.monotonic() + timeout_seconds
    about = None
    while time.monotonic() < deadline:
        try:
            with urlopen(base_url + "/about", timeout=3) as response:
                if response.status == 200:
                    about = response.read().decode("utf-8")
                    break
        except (HTTPError, URLError, OSError, TimeoutError):
            pass
        time.sleep(1)
    if about is None:
        raise RuntimeError("service_did_not_start")
    if expected_commit[:7] not in about or expected_commit not in about:
        raise RuntimeError("service_provenance_mismatch")
    with urlopen(base_url + "/operations/", timeout=5) as response:
        if response.status != 200 or not response.url.startswith(base_url + "/login"):
            raise RuntimeError("service_authentication_boundary_failed")
    return {"entrypoint": "ok", "http": "ok", "source": "ok", "authentication": "ok"}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--expected-commit", required=True)
    args = parser.parse_args()
    print(check_service(args.base_url, args.expected_commit))


if __name__ == "__main__":
    main()
