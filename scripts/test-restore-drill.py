"""Run preflight checks without credentials, Docker, or network access."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).with_name("restore-drill.sh").resolve()


class PreflightTest(unittest.TestCase):
    def run_drill(self, **overrides):
        with tempfile.TemporaryDirectory() as tmp:
            for tool in ("docker", "psql", "wrangler", "pnpm"):
                stub = Path(tmp, tool)
                stub.write_text('#!/bin/sh\n[ "$1" = rm ] && exit 0\necho UNEXPECTED_EXTERNAL_CALL >&2\nexit 97\n')
                stub.chmod(0o755)
            env = {"PATH": tmp + os.pathsep + os.defpath,
                   "CLOUDFLARE_ACCOUNT_ID": "test-account",
                   "CLOUDFLARE_API_TOKEN": "test-token",
                   "PACT_DRILL_WORKSPACE_ID": "test-workspace",
                   "R2_DUMP_KEY": "postgres/test.sql.gz"}
            env.update(overrides)
            return subprocess.run(["bash", str(SCRIPT)], env=env,
                                  text=True, capture_output=True, timeout=5)

    def test_missing_inputs_stop_before_external_work(self):
        for name in ("CLOUDFLARE_ACCOUNT_ID", "CLOUDFLARE_API_TOKEN",
                     "PACT_DRILL_WORKSPACE_ID", "R2_DUMP_KEY"):
            with self.subTest(name=name):
                result = self.run_drill(**{name: ""})
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn(name, result.stderr)
                self.assertNotIn("UNEXPECTED_EXTERNAL_CALL", result.stderr)

    def test_wrong_prefix_stops_before_external_work(self):
        result = self.run_drill(R2_DUMP_KEY="other/test.sql.gz")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertNotIn("UNEXPECTED_EXTERNAL_CALL", result.stderr)

    def test_valid_configuration_reaches_container_boundary(self):
        result = self.run_drill()
        self.assertEqual(result.returncode, 97, result.stderr)
        self.assertIn("UNEXPECTED_EXTERNAL_CALL", result.stderr)


if __name__ == "__main__":
    unittest.main()
