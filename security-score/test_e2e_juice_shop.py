"""Opt-in live CLI tests against the public Juice Shop repository.

Run with SECURITY_SCORE_LIVE_E2E=1 using Python with the declared build tools.
By default, build and install the current checkout in an isolated environment.
SECURITY_SCORE_E2E_EXECUTABLE can select an already installed absolute CLI path.
No Juice Shop code, dependencies, tests or build scripts are executed.
"""

import json
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import venv
import zipfile


ROOT = Path(__file__).resolve().parent
REPOSITORY = "https://github.com/juice-shop/juice-shop"
SCORE_LINE = r"(100|[1-9]?\d)/100 \((partial|[A-F])\)"


@unittest.skipUnless(
    os.environ.get("SECURITY_SCORE_LIVE_E2E") == "1",
    "Live GitHub test: set SECURITY_SCORE_LIVE_E2E=1 to run explicitly.",
)
class JuiceShopE2ETests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.artifacts = ROOT / "out" / "juice-shop-e2e"
        cls.artifacts.mkdir(parents=True, exist_ok=True)
        cls.temporary = tempfile.TemporaryDirectory(prefix="score-live-e2e-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.work = Path(cls.temporary.name)
        cls.environment = {
            key: value
            for key, value in os.environ.items()
            if key not in {"PYTHONPATH", "PYTHONHOME"}
        }
        selected = os.environ.get("SECURITY_SCORE_E2E_EXECUTABLE")
        provenance = {}
        if selected:
            cls.executable = Path(selected)
            if not cls.executable.is_absolute() or not cls.executable.is_file():
                raise AssertionError(
                    "SECURITY_SCORE_E2E_EXECUTABLE must name an installed absolute executable."
                )
            cls.executable = cls.executable.resolve()
        else:
            source = cls.work / "source"
            shutil.copytree(
                ROOT,
                source,
                ignore=shutil.ignore_patterns(
                    "build",
                    "out",
                    "*.egg-info",
                    "__pycache__",
                    ".venv",
                ),
            )
            cls.build(
                sys.executable,
                "-m",
                "pip",
                "wheel",
                "--no-index",
                "--no-deps",
                "--no-build-isolation",
                "--no-cache-dir",
                "--wheel-dir",
                str(cls.work / "wheels"),
                str(source),
            )
            wheel = next((cls.work / "wheels").glob("*.whl"))
            with zipfile.ZipFile(wheel) as packaged:
                for path in (source / "scripts").glob("*.py"):
                    content = path.read_bytes()
                    if packaged.read(path.name) != content:
                        raise AssertionError(
                            f"Wheel does not contain the current {path.name}."
                        )
                    provenance[path.name] = hashlib.sha256(content).hexdigest()
                rules = next(
                    name
                    for name in packaged.namelist()
                    if name.endswith("/share/security-score/rules.json")
                )
                if packaged.read(rules) != (source / "rules.json").read_bytes():
                    raise AssertionError(
                        "Wheel does not contain the current bundled rules."
                    )
            provenance["wheel_sha256"] = hashlib.sha256(wheel.read_bytes()).hexdigest()
            environment = cls.work / "venv"
            venv.EnvBuilder(with_pip=False).create(environment)
            cls.build(
                sys.executable,
                "-m",
                "pip",
                "--python",
                str(environment / "bin" / "python"),
                "install",
                "--no-index",
                "--no-deps",
                str(wheel),
            )
            cls.executable = environment / "bin" / "security-score"
            shutil.copy2(wheel, cls.artifacts / wheel.name)
        version = cls.build(str(cls.executable), "--version").stdout.strip()
        (cls.artifacts / "installation.json").write_text(
            json.dumps(
                {
                    "executable": str(cls.executable),
                    "version": version,
                    "repository": REPOSITORY,
                    "fresh_wheel": not bool(selected),
                    "provenance": provenance,
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        print(f"\nLive E2E: {version}; artifacts: {cls.artifacts}", flush=True)

    @classmethod
    def build(cls, *arguments):
        result = subprocess.run(
            arguments,
            cwd=cls.work,
            env=cls.environment,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=60,
        )
        if result.returncode:
            raise AssertionError(f"E2E installation failed: {result.stderr[-4000:]}")
        return result

    def run_mode(self, name, *flags):
        started = time.monotonic()
        try:
            result = subprocess.run(
                [str(self.executable), REPOSITORY, *flags],
                cwd=self.work,
                env=self.environment,
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=70,
            )
        except subprocess.TimeoutExpired as error:
            self.fail(
                f"{name}: CLI exceeded the 70-second outer deadline: {error.timeout}s"
            )
        elapsed = time.monotonic() - started
        (self.artifacts / f"{name}.stdout.txt").write_text(
            result.stdout, encoding="utf-8"
        )
        (self.artifacts / f"{name}.stderr.txt").write_text(
            result.stderr, encoding="utf-8"
        )
        (self.artifacts / f"{name}.json").write_text(
            json.dumps(
                {
                    "flags": list(flags),
                    "exit_status": result.returncode,
                    "seconds": round(elapsed, 3),
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        print(f"  {name}: {elapsed:.1f}s, exit {result.returncode}", flush=True)
        self.assertIn(
            result.returncode, (0, 1, 2), f"{name}: CLI failed: {result.stderr}"
        )
        self.assertLess(elapsed, 70)
        self.assertNotIn("Traceback", result.stdout + result.stderr)
        return result

    def check_score(self, match, result):
        self.assertIsNotNone(
            match, f"No numeric indication: {result.stdout!r}; {result.stderr!r}"
        )
        if match[2] == "partial":
            self.assertIn(result.returncode, (1, 2))
        else:
            self.assertEqual(result.returncode, 0)

    def test_default_shows_progress_and_one_result_without_details(self):
        result = self.run_mode("default")
        self.check_score(re.fullmatch(SCORE_LINE + r"\n", result.stdout), result)
        self.assertIn("Reading selected sources...", result.stderr)
        self.assertIn("Checking source patterns...", result.stderr)
        self.assertNotIn("Categories", result.stdout)
        self.assertNotIn("Findings", result.stdout)
        self.assertNotIn("Calculation", result.stdout)

    def test_detail_has_topic_subscores_with_a_few_examples_directly_below(self):
        result = self.run_mode("detail", "--details")
        overall = re.search(
            r"(?m)^Security score . " + SCORE_LINE + r"$", result.stdout
        )
        self.check_score(overall, result)
        self.assertIn("Reading selected sources...", result.stderr)
        output = result.stdout
        self.assertNotIn("\033", output)
        headings = list(
            re.finditer(
                r"(?m)^(Repository|Authentication|Architecture|Frontend|Dependencies & CI|Secrets|Cryptography|Deployment & transport) +(not assessed|(100|[1-9]?\d)/100)\b.*$",
                output,
            )
        )
        self.assertEqual(
            [match[1] for match in headings],
            [
                "Repository",
                "Authentication",
                "Architecture",
                "Frontend",
                "Dependencies & CI",
                "Secrets",
                "Cryptography",
                "Deployment & transport",
            ],
        )
        self.assertRegex(output, r"(?m)^Authentication +not assessed")
        scores = []
        for number, heading in enumerate(headings):
            end = (
                headings[number + 1].start()
                if number + 1 < len(headings)
                else output.index("\nCoverage\n")
            )
            block = output[heading.end() : end]
            tags = re.findall(r"(?m)^  (?:CRITICAL|HIGH|MEDIUM|LOW) ", block)
            positive = re.findall(r"(?m)^  OK ", block)
            self.assertGreaterEqual(len(re.findall(r"(?m)^  \S", block)), 1, heading[1])
            self.assertLessEqual(len(tags), 3, heading[1])
            self.assertLessEqual(len(positive), 2, heading[1])
            if heading[2] != "not assessed":
                scores.append(int(heading[3]))
        self.assertEqual(int(overall[1]), min(scores))
        self.assertRegex(output, r"(?m)^  (?:CRITICAL|HIGH|MEDIUM|LOW) +\S")
        self.assertRegex(
            output,
            r"(?m)^ {12}[A-Z][A-Z0-9-]+ . (?:lib|routes|frontend|scripts)/\S+:\d+",
        )
        # helmet.noSniff() and helmet.frameguard() in server.ts are positive evidence.
        self.assertRegex(output, r"(?m)^ {12}WEB-HEADERS . server\.ts:\d+")
        counts = re.findall(r"(?m)^[A-Z].*?(\d+) findings?$", output)
        total = re.search(r"\d+ files? checked . (\d+) findings?", output)
        self.assertIsNotNone(total)
        self.assertEqual(sum(map(int, counts)), int(total[1]))
        for debug_fragment in (
            "score=withheld",
            "observed=None",
            "floor=0",
            "Calculation ",
            "Candidate groups",
            "Deduction",
            "\nCategories\n",
            "\nFindings\n",
        ):
            self.assertNotIn(debug_fragment, output)

    def test_quite_has_only_the_integer_and_no_progress(self):
        result = self.run_mode("quite", "--quite")
        self.assertRegex(result.stdout, r"\A(?:100|[1-9]?\d)\n\Z")
        self.assertEqual(result.stderr, "")


if __name__ == "__main__":
    unittest.main()
