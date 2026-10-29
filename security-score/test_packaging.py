"""Offline release verification; requires the declared setuptools/wheel build tools."""

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import venv
import zipfile


ROOT = Path(__file__).resolve().parent


class PackagingTests(unittest.TestCase):
    def test_sdist_wheel_and_installed_cli_preserve_source_commit(self):
        with tempfile.TemporaryDirectory(prefix="score-release-test-") as temporary:
            root = Path(temporary)
            source = root / "source"
            shutil.copytree(
                ROOT,
                source,
                ignore=shutil.ignore_patterns("build", "*.egg-info", "__pycache__"),
            )

            def run(*args, cwd=source, env=None):
                result = subprocess.run(
                    args, cwd=cwd, env=env, capture_output=True, text=True, timeout=60
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                return result.stdout.strip()

            def git(*args):
                return run(
                    "git",
                    "-c",
                    "core.hooksPath=/dev/null",
                    "-c",
                    "user.name=Release test",
                    "-c",
                    "user.email=release@example.invalid",
                    *args,
                )

            git("init", "-b", "main")
            git("add", ".")
            git("commit", "--no-gpg-sign", "-m", "Synthetic release")
            commit = git("rev-parse", "HEAD")
            run(sys.executable, "setup.py", "sdist", "--dist-dir", str(root / "sdist"))
            archive = next((root / "sdist").glob("*.tar.gz"))
            run(
                sys.executable,
                "-m",
                "pip",
                "wheel",
                "--no-index",
                "--no-deps",
                "--no-build-isolation",
                "--no-cache-dir",
                "--wheel-dir",
                str(root / "wheels"),
                str(archive),
            )
            wheel = next((root / "wheels").glob("*.whl"))
            with zipfile.ZipFile(wheel) as packaged:
                self.assertIn("_security_score_build.py", packaged.namelist())
                self.assertIn(
                    commit, packaged.read("_security_score_build.py").decode()
                )
                self.assertIn("score_remote_sources.py", packaged.namelist())
            environment = root / "venv"
            venv.EnvBuilder(with_pip=False).create(environment)
            python = environment / "bin" / "python"
            run(
                sys.executable,
                "-m",
                "pip",
                "--python",
                str(python),
                "install",
                "--no-index",
                "--no-deps",
                str(wheel),
            )
            output = run(
                str(environment / "bin" / "security-score"),
                "--version",
                cwd=root,
                env={**os.environ, "PATH": ""},
            )
            self.assertEqual(output, f"security-score 0.1.6 (commit {commit})")


if __name__ == "__main__":
    unittest.main()
