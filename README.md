# HIPAA Package for Django

This is a collection of monkey patches and utilties to make a site more HIPAA friendly.

# Features

- Rate limits the `django.contrib.auth.forms.AuthenticationForm` and resets that rate limit when `django.contrib.auth.forms.SetPasswordForm` is saved.
- Provides an abstract base model for simple Logging capabilities (which many of this package's features rely on)
- Automatically logs out a user after a configurable amount of inactivity. A simple JavaScript pinging mechanism is used to prevent logouts when the user is actively engaged on a single page for a long time.
- Ensures passwords are complex
- Python 3+ only

# Assumptions

- You're using the SessionMiddleware, AuthenticationMiddleware, MessageMiddleware.
- You use the `AuthenticationForm` and `SetPasswordForm` from `django.contrib.auth.forms` to authenticate users and reset passwords.
- You can stomach the idea of monkey patching to minimize changes to the consumer of this package.
- You're running jQuery on the client side

# Install

    pip install -e this package

After `SessionMiddleware`, `AuthenticationMiddleware` and `MessageMiddleware`, append **`hipaa.middleware.StillAliveMiddleware` to `MIDDLEWARE_CLASSES`**

Add 'hipaa' to INSTALLED_APPS.

Somewhere in your app, create a model that is a subclass of `hipaa.Log`:

    # utils/models.py

    from hipaa.models import Log, LogModelField

    class Log(Log):
        # this creates a ForeignKey to Car that you can use when logging an event
        car = LogModelField("cars.Car")

        class Meta:
            db_table = "log"


Add some settings to your project:

    # project/settings.py
    from datetime import timedelta

    AUTOMATIC_LOGOUT_AFTER = timedelta(minutes=15)
    # 20 login attempts per 10 minutes
    LOGIN_RATE_LIMIT = (20, timedelta(minutes=10))


# Usage

## Logging

To log events, use Log.info(), Log.warning(), Log.error() and Log.critical()

The arguments are: `request=None, action="", extra="", user=None, ip_address=None, **loggable_model_fields`. If you pass in an HttpRequest object, the user and ip address will be determined automatically.

```python
# assuming this is where your subclass of hipaa.models.Log is located...
from project.utils.models import Log
# assuming your subclass of Log has a LogModelField pointed at cars.Car
from project.cars.models import Car

def some_django_view(request, car_id)
    car = get_object_or_404(Car, pk=car_id)
    # this creates a log entry that records the IP address of the request,
    # and the user (if the user is authenticated), with a reference to the
    # car object
    Log.info(
        # pass the request object to get the IP address and user
        request=request,
        # `action` is just a string but to avoid string typing, there are a few
        # built in constants like Log.CREATED, Log.EDITED, Log.DELETED,
        # Log.VIEWED
        action=Log.VIEWED,
        extra="some abitrary text content",
        car=car
    )

    return render(request, "cars/detail.html", {"car": car})
```

`Log` is just a normal django model, so you can query it like `Log.objects.filter(...)`.

### Deletions

In the example above, if the Car object was deleted, the `car` field on the Log entry would be set to null. This is problematic because you lose important information about the log entry (i.e. what car it was in reference to). To get around this problem, a special field called `fieldname_pk` on the Log model (where `fieldname` is the name of the field) is automatically created when you declare a `LogModelField`. It contains the string PK of the model the log entry is for. In this example, there is a field on the Log model called "car_pk" which contains the PK of the car object it referenced.

## Timeout

Add `<script src="{{ STATIC_URL }}hipaa/ping.js"></script>` to your base Django template (after jQuery is included) to ping the site every 5 minutes (by default). This will prevent the user from being logged out if they stay on the same page for a long time.

If you set HIPAA_MILLISECONDS_BETWEEN_PINGS in JavaScript land before the script is included, then it will use that instead of the 5 minute default.
