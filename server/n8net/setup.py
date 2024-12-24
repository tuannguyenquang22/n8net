from setuptools import setup
from Cython.Build import cythonize

setup(
    ext_modules=cythonize("server.pyx", language_level=3),
)

