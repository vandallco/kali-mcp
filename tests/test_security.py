"""Tests de los controles de seguridad de kali-mcp (allowlist, confinamiento de rutas y auth)."""

import importlib
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

TOKEN = "t" * 40


def load_server(**env):
    """Importa server.py con las variables de entorno indicadas."""
    state = tempfile.mkdtemp()
    base = {"KALI_MCP_STATE_DIR": state, "KALI_MCP_TOKEN": TOKEN}
    base.update(env)
    for k in [k for k in os.environ if k.startswith("KALI_MCP_")]:
        del os.environ[k]
    os.environ.update(base)
    if "server" in sys.modules:
        del sys.modules["server"]
    return importlib.import_module("server")


class AllowlistTests(unittest.TestCase):
    def setUp(self):
        self.srv = load_server(KALI_MCP_ALLOWED_COMMANDS="nmap,whois,grep,dig")

    def test_allowed_binary(self):
        self.assertIsNone(self.srv.check_command("nmap -sV 10.0.0.5"))

    def test_allowed_pipeline(self):
        self.assertIsNone(self.srv.check_command("whois example.com | grep -i registrar"))

    def test_env_assignment_prefix(self):
        self.assertIsNone(self.srv.check_command("LANG=C dig example.com"))

    def test_denied_binary(self):
        self.assertIn("rm", self.srv.check_command("rm -rf /"))

    def test_denied_in_chain(self):
        self.assertIsNotNone(self.srv.check_command("nmap 10.0.0.5; curl http://evil"))
        self.assertIsNotNone(self.srv.check_command("nmap 10.0.0.5 && bash -i"))

    def test_command_substitution_blocked(self):
        self.assertIsNotNone(self.srv.check_command("nmap $(cat targets)"))
        self.assertIsNotNone(self.srv.check_command("nmap `id`"))

    def test_absolute_path_uses_basename(self):
        self.assertIsNone(self.srv.check_command("/usr/bin/nmap -p 22 host"))

    def test_no_allowlist_allows_everything(self):
        srv = load_server()
        self.assertIsNone(srv.check_command("anything --goes"))


class PathConfinementTests(unittest.TestCase):
    def setUp(self):
        self.workdir = Path(tempfile.mkdtemp()).resolve()
        self.srv = load_server(KALI_MCP_WORKDIR=str(self.workdir))

    def test_inside_workdir(self):
        self.assertEqual(self.srv._resolve_confined("notas.txt"), self.workdir / "notas.txt")

    def test_traversal_blocked(self):
        with self.assertRaises(PermissionError):
            self.srv._resolve_confined("../../etc/passwd")

    def test_absolute_outside_blocked(self):
        outside = Path(tempfile.mkdtemp()).resolve() / "x.txt"
        with self.assertRaises(PermissionError):
            self.srv._resolve_confined(str(outside))

    def test_write_file_denied_outside(self):
        self.assertTrue(self.srv.write_file("../fuera.txt", "x").startswith("[denegado]"))

    def test_restriction_can_be_disabled(self):
        srv = load_server(KALI_MCP_WORKDIR=str(self.workdir), KALI_MCP_RESTRICT_PATHS="false")
        srv._resolve_confined("../x.txt")  # no lanza excepción


class AuthTests(unittest.TestCase):
    def setUp(self):
        from starlette.testclient import TestClient

        self.srv = load_server()
        self.client = TestClient(self.srv.build_app(), base_url="http://127.0.0.1:8765")
        self.client.__enter__()

    def tearDown(self):
        self.client.__exit__(None, None, None)

    def _init(self, headers):
        body = {
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-03-26", "capabilities": {},
                       "clientInfo": {"name": "test", "version": "0"}},
        }
        base = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
        return self.client.post("/mcp", json=body, headers={**base, **headers})

    def test_missing_token_rejected(self):
        self.assertEqual(self._init({}).status_code, 401)

    def test_wrong_token_rejected(self):
        self.assertEqual(self._init({"Authorization": "Bearer nope"}).status_code, 401)

    def test_valid_token_accepted(self):
        self.assertEqual(self._init({"Authorization": f"Bearer {TOKEN}"}).status_code, 200)

    def test_auth_failures_are_audited(self):
        self._init({})
        log = self.srv.AUDIT_LOG.read_text(encoding="utf-8")
        self.assertIn('"auth_failed"', log)


if __name__ == "__main__":
    unittest.main()
