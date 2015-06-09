import sys
from setuptools import find_packages, setup

setup(
    name='hipaa',
    version='0.0.1',
    install_requires=['django-ipware'],
    packages=find_packages(),
    long_description=open('README.md').read(),
    author='Matt Johnson',
    extras_require={
        'dev': [
            "mock",
            "model_mommy",
            "coverage",
            "django" + ("<1.7" if sys.version_info[:2] < (2, 7) else "")
        ],
    }
)
