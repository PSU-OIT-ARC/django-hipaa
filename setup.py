import sys

from setuptools import find_packages, setup


DJANGO_VERSION_SPEC = '<1.7' if sys.version_info[:2] < (2, 7) else ''


setup(
    name='hipaa',
    version='0.0.1',
    install_requires=['django-ipware'],
    packages=find_packages(),
    include_package_data=True,
    long_description=open('README.md').read(),
    author='PSU - OIT - ARC',
    author_email='consultants@pdx.edu',
    extras_require={
        'dev': [
            'mock',
            'model_mommy',
            'coverage',
            'flake8',
            'isort',
            'django{version_spec}'.format(version_spec=DJANGO_VERSION_SPEC),
        ],
    }
)
