"""Incluye el stack congelado también en instalaciones no editables."""
from pathlib import Path
import shutil

from setuptools import setup
from setuptools.command.build_py import build_py


class BuildWithPlayground(build_py):
    def run(self):
        super().run()
        source = Path(__file__).parent / "playground-stack"
        target = Path(self.build_lib) / "apate" / "playground" / "_stack"
        for path in sorted(source.rglob("*")):
            relative = path.relative_to(source)
            if any(part in {".git", "node_modules", "__pycache__", "logs"} for part in relative.parts):
                continue
            if path.is_symlink():
                raise ValueError("El stack distribuido no admite enlaces simbólicos")
            if path.is_file():
                destination = target / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(path, destination)


setup(cmdclass={"build_py": BuildWithPlayground})
