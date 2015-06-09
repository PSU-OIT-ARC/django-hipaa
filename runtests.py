from datetime import timedelta
import sys

import django
from django.conf import settings

settings.configure(
    DEBUG=True,
    DATABASES={
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
        }
    },
    INSTALLED_APPS=(
        'django.contrib.auth',
        'django.contrib.contenttypes',
        'django.contrib.sessions',
        'django.contrib.admin',
        'django.contrib.messages',
        'django.contrib.staticfiles',
        # this is only needed so Django can find the tests
        'hipaa',
    ),
    MIDDLEWARE_CLASSES=[
        'django.contrib.sessions.middleware.SessionMiddleware',
        'django.middleware.common.CommonMiddleware',
        'django.middleware.csrf.CsrfViewMiddleware',
        'django.contrib.auth.middleware.AuthenticationMiddleware',
        'django.contrib.messages.middleware.MessageMiddleware',
        'hipaa.middleware.StillAliveMiddleware',
    ],
    USE_TZ=True,
    AUTOMATIC_LOGOUT_AFTER=timedelta(seconds=5),
    LOGIN_RATE_LIMIT=(2, timedelta(seconds=.25)),
    LOGIN_URL="/login",
)

if django.VERSION[:2] >= (1, 7):
    from django import setup
else:
    setup = lambda: None

from django.test.runner import DiscoverRunner

setup()
test_runner = DiscoverRunner(verbosity=1)

failures = test_runner.run_tests(['hipaa', ])
if failures:
    sys.exit(failures)
