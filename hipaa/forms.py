from datetime import timedelta

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.forms import AuthenticationForm, SetPasswordForm
from django.core.exceptions import ImproperlyConfigured
from django.forms import ValidationError
from django.utils.timezone import now

from .models import Log

LOGIN_RATE_LIMIT = getattr(settings, "LOGIN_RATE_LIMIT", (20, timedelta(minutes=10)))


def get_logger():
    """
    Returns the (first) Log class that subclasses this package's Log model
    """
    try:
        Logger = list(Log.__subclasses__())[0]
    except IndexError:
        raise ImproperlyConfigured("You must have a model subclass of 'hipaa.Log'")

    return Logger


# Monkey patches the AuthenticationForm.clean method so it takes into account the
# LOGIN_RATE_LIMIT
clean = AuthenticationForm.clean


def rate_limiting_clean(self):
    """
    This adds rate limiting to the login form
    """
    Logger = get_logger()
    # if there was no username, no need to consider a ratelimit
    if self.cleaned_data.get("username"):
        # we key the rate limit based on the username on the form entered, and the
        # IP address
        log_info = Logger.info(
            request=self.request,
            action=Log.PASSWORD_ATTEMPT,
            extra=self.cleaned_data.get("username")
        )

        # this is the date to go back in the Log records to find out how many
        # logins have been performed in the set amount of time
        offset_date = now() - LOGIN_RATE_LIMIT[1]

        # figure out when the last password reset action was performed, so we
        # can use *that* as the offset date instead (so after you reset your
        # password, you can always log back in). This won't work if someone is
        # purposely trying to DOS you (but we won't handle that case)
        UserModel = get_user_model()
        user = UserModel.objects.filter(**{self.username_field.name: self.cleaned_data.get("username")}).first()
        last_reset = Logger.objects.filter(action=Log.PASSWORD_RESET, user=user).order_by("-pk").exclude(user=None).first()
        if last_reset:
            offset_date = max(last_reset.created_on, offset_date)

        # if there were too many attempts, raise a validation error
        if Logger.objects.filter(
                ip_address=log_info.ip_address,
                action=Log.PASSWORD_ATTEMPT,
                extra=self.cleaned_data.get("username"),
                created_on__gte=offset_date).count() > LOGIN_RATE_LIMIT[0]:
            raise ValidationError(
                "Too many login attempts. You can reset your password to login again or wait %d seconds"
                % LOGIN_RATE_LIMIT[1].total_seconds()
            )

    return clean(self)

AuthenticationForm.clean = rate_limiting_clean


# hook into the SetPasswordForm (which is used to reset a password), so we can
# log it happened
save = SetPasswordForm.save


def log_password_change(self):
    """
    This adds logging to the SetPasswordForm which is used when a password is
    being reset
    """
    Logger = get_logger()
    Logger.info(action=Logger.PASSWORD_RESET, user=self.user)
    save(self)

SetPasswordForm.save = log_password_change
