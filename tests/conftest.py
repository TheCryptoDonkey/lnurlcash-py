"""Fixtures: the shared conformance vectors, and the adversarial mock mint.

The mock mint is a Node process from the lnurlcash-conformance repo, spawned
per test with whatever misbehaviour that test needs. Running the real server
rather than stubbing httpx is deliberate: a stub would only ever fail in ways
this library already anticipates, and the interesting failures are the ones it
does not.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest

CONFORMANCE = Path(
    os.environ.get(
        "LNURLCASH_CONFORMANCE",
        Path(__file__).resolve().parents[2] / "lnurlcash-conformance",
    )
)
VECTORS = CONFORMANCE / "vectors"

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


def load_vectors(name: str) -> dict:
    path = VECTORS / name
    if not path.exists():
        pytest.skip(f"conformance vectors not found at {VECTORS}")
    return json.loads(path.read_text())


@pytest.fixture(scope="session")
def node() -> str:
    found = shutil.which("node")
    if not found:
        pytest.skip("node is required to run the mock mint")
    return found


class MockMint:
    def __init__(self, url: str, note: str | None, pubkey: str, process) -> None:
        self.url = url
        self.note = note
        self.pubkey = pubkey
        self._process = process

    def credit(self, k1: str, amount_msat: int) -> str | None:
        """Bring a note into existence, via the mock's test hooks. Returns the
        signature the mint issued for it, if it signs."""
        body = httpx.get(
            f"{self.url}/_test/credit", params={"k1": k1, "amount": amount_msat}
        ).json()
        assert body["status"] == "OK", body
        return body.get("c") or body.get("sig")

    def settle(self, payment_hash: str) -> None:
        """Mark an invoice paid. The mock invents its invoices, so nothing can
        ever pay one for real - this is what standing in for the payment
        looks like."""
        body = httpx.get(
            f"{self.url}/_test/settle", params={"payment_hash": payment_hash}
        ).json()
        assert body["status"] == "OK", body

    def note_state(self, k1: str) -> str | None:
        """What the SERVICE thinks of a note: outstanding, pending or burned.
        Asserting against this rather than against the SERVICE's own replies is
        the point - it is the difference between what a mint says and what it
        did."""
        body = httpx.get(f"{self.url}/_test/state", params={"k1": k1}).json()
        assert body["status"] == "OK", body
        return body["state"]

    def note_url(self, k1: str, amount_msat: int | None = None) -> str:
        url = f"{self.url}/w?k1={k1}"
        return f"{url}&amount={amount_msat}" if amount_msat is not None else url

    def close(self) -> None:
        self._process.terminate()
        try:
            self._process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self._process.kill()


@pytest.fixture
def mint(node):
    """Spawns mock mints. Call with the misbehaviour flags a test needs."""
    started: list[MockMint] = []

    def _start(**flags) -> MockMint:
        script = CONFORMANCE / "mock-mint" / "index.mjs"
        if not script.exists():
            pytest.skip(f"mock mint not found at {script}")
        args = [node, str(script), "--port=0", "--testHooks=true"]
        for key, value in flags.items():
            args.append(f"--{key}={json.dumps(value) if isinstance(value, bool) else value}")
        process = subprocess.Popen(
            args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
        )
        url = note = pubkey = None
        deadline = time.time() + 15
        while time.time() < deadline:
            line = process.stdout.readline()
            if not line:
                break
            if match := re.search(r"listening on (http://\S+)", line):
                url = match.group(1)
            if match := re.search(r"(lnurlw://\S+)", line):
                note = match.group(1)
            if match := re.search(r"mint pubkey:\s+([0-9a-f]+)", line):
                pubkey = match.group(1)
            if url and note and pubkey:
                break
        if not url:
            process.kill()
            pytest.fail("the mock mint did not start")
        m = MockMint(url, note, pubkey, process)
        started.append(m)
        return m

    yield _start
    for m in started:
        m.close()
