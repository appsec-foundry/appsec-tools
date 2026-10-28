"""Embed the source revision in wheels and source distributions."""

from pathlib import Path
import sys

from setuptools import setup
from setuptools.command.build_py import build_py
from setuptools.command.sdist import sdist

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "scripts"))
from score_version import identity  # noqa: E402


def write_identity(directory, build):
    path = Path(directory) / "_security_score_build.py"
    path.write_text(
        f"# Generated release identity; no runtime Git required.\nBUILD = {build!r}\n"
    )


class BuildWithIdentity(build_py):
    def run(self):
        build = identity()
        super().run()
        write_identity(self.build_lib, build)


class SourceWithIdentity(sdist):
    def make_release_tree(self, base_dir, files):
        build = identity()
        super().make_release_tree(base_dir, files)
        write_identity(Path(base_dir) / "scripts", build)


setup(cmdclass={"build_py": BuildWithIdentity, "sdist": SourceWithIdentity})
