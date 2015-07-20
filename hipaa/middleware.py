import math
import time
from datetime import timedelta

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import logout
from django.http import JsonResponse

PING_TIMESTAMP_SESSION_NAME = "HIPAA_LAST_PING"
# the header name for the ping request is X-HIPAA-PING but Django transforms
# the header so it is prefixed with HTTP_, and the dashes are underscores
HIPAA_PING_HEADER_NAME = "HTTP_" + "X-HIPAA-PING".replace("-", "_")
# the amount of time before an automatic logout should happen
AUTOMATIC_LOGOUT_AFTER = getattr(settings, "AUTOMATIC_LOGOUT_AFTER", timedelta(minutes=15))


class StillAliveMiddleware:
    """
    This middleware checks to see if the last request was made within a
    reasonable amount of time. If not, then it redirects to the login page.
    This middleware also handles intercepting "pings" from the JavaScript, that
    indiciate activity on the page.

    Periodically, an AJAX request is received containing a header X-HIPPA-PING.
    If the header is set to 1, it means the user moved their mouse on the page
    (or something like that). If it is zero, it means they haven't done
    anything since the last ping.
    """
    def process_request(self, request):
        now = int(time.time())
        if request.user.is_authenticated():
            # check to see if the last request made by the user was within a
            # reasonable amount of time
            last_ping = int(request.session.get(PING_TIMESTAMP_SESSION_NAME, time.time()))
            if timedelta(seconds=now-last_ping) > AUTOMATIC_LOGOUT_AFTER:
                logout(request)
                messages.warning(request, "You have been logged out for inactivity.")

        # if there is an X-HIPPA-PING header, then we check to see if it is 1,
        # which indicates that the ping time should be updated because of
        # activity. If it is just a normal request (without the
        # X-HTTP_X_HIPAA_PING header) then we want to update the time too
        # (that's why the default for request.META.get is "1")
        if int(request.META.get(HIPAA_PING_HEADER_NAME, "1")) == 1:
            request.session[PING_TIMESTAMP_SESSION_NAME] = now

        # figure out when the next ping should be
        seconds_since_last_ping = (now - request.session.get(PING_TIMESTAMP_SESSION_NAME, now))
        seconds_before_logout = AUTOMATIC_LOGOUT_AFTER.total_seconds() - seconds_since_last_ping
        # use exponential decay for the ping times, so as we get closer to
        # being logged out, we ping more often so we can detect activity
        seconds_until_next_ping = max(1, seconds_before_logout/2.0)

        # we don't need to ping for anonymous users
        if not request.user.is_authenticated():
            # any large number will do (but it can't be more than (2**31-1)/1000),
            # since JavaScript timers use signed 32-bit ints (in units of
            # milliseconds)
            seconds_until_next_ping = math.floor((2**31-1)/1000)

        if HIPAA_PING_HEADER_NAME in request.META:
            return JsonResponse({
                "state": "authenticated" if request.user.is_authenticated() else "unauthenticated",
                "seconds_until_next_ping": seconds_until_next_ping
            })
        else:
            # nothing to do
            return None
