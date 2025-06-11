from setuptools import setup
from setuptools_rust import Binding, RustExtension

from pathlib import Path

this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text()

setup(
    name="ferveo",
    description="Ferveo DKG scheme",
    long_description=long_description,
    long_description_content_type="text/markdown",
    version="0.1.13",
    author="David Nuñez",
    author_email="david@nucypher.com",
    url="https://github.com/nucypher/ferveo/tree/master/ferveo-python",
    rust_extensions=[
        RustExtension("ferveo._ferveo", binding=Binding.PyO3, debug=False)
    ],
    packages=["ferveo"],
    package_data={
        "ferveo": ["py.typed", "__init__.pyi"],
    },
    # rust extensions are not zip safe, just like C-extensions.
    zip_safe=False,
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Natural Language :: English",
        "Programming Language :: Rust",
        "Programming Language :: Python :: Implementation :: CPython",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security :: Cryptography",
    ],
)
