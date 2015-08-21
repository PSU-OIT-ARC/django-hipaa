import json
import time
from datetime import timedelta
from unittest.mock import Mock, patch

from django.conf import settings
from django.contrib.auth.models import User
from django.contrib.auth.views import password_change
from django.core.exceptions import NON_FIELD_ERRORS
from django.core.urlresolvers import reverse
from django.db import models
from django.forms import ValidationError
from django.test import TestCase
from django.utils.timezone import now
from model_mommy.mommy import make

from .forms import (
    AuthenticationForm,
    PasswordResetForm,
    SetPasswordForm,
    authentication_form_clean,
    get_logger,
)
from .middleware import (
    REQUIRE_PASSWORD_RESET_AFTER,
    REQUIRE_PASSWORD_RESET_FOR_STAFF_AFTER,
    RequirePasswordChangeMiddleware,
    StillAliveMiddleware,
)
from .models import Log, LogModelField


class Car(models.Model):
    pass


class SomeReallyLongName(models.Model):
    pass


class Logger(Log):
    car = LogModelField(Car)
    something = LogModelField(SomeReallyLongName)


class LogTest(TestCase):
    def test(self):
        # make sure the log entry is created
        car = make(Car)
        Logger.info(car=car, action="created", extra="hello")
        self.assertTrue(Logger.objects.filter(car=car).exists())

        # make sure the ip address and user is populated
        user = make(User)
        user.is_authenticated = lambda: True
        request = Mock(user=user, META={"REMOTE_ADDR": '8.8.8.8'})
        entry = Logger.info(request=request, action="foo")
        self.assertEqual(entry.user, user)
        self.assertEqual(entry.ip_address, "8.8.8.8")


class LogModelFieldTest(TestCase):
    def test(self):
        # make sure the magic `name`_pk fields get added for all LogModelField
        # fields on the Log subclass
        logger = make(Logger)
        self.assertIn("car_pk", dir(logger))
        self.assertIn("something_pk", dir(logger))


class PDXEmailAddressesRequireCASLogin(TestCase):
    def test_cas_login_required_for_pdx_emails(self):
        form = AuthenticationForm(data={"username": "foo@pdx.EDU", "password": "lame"})
        self.assertFalse(form.is_valid())
        self.assertIn("You must sign in with CAS", str(form.errors))

        # if it's not a pdx.edu email address, then logging in should not raise that error
        form = AuthenticationForm(data={"username": "foo@pdx.eduuu", "password": "lame"})
        self.assertFalse(form.is_valid())
        self.assertNotIn("You must sign in with CAS", str(form.errors))


class RateLimitingOnLoginTest(TestCase):
    def test_nothing_happens_if_username_is_blank(self):
        with patch("hipaa.forms.AuthenticationForm.clean") as clean:
            logger = Mock()
            with patch("hipaa.forms.get_logger", return_value=logger) as clean:
                form = Mock(cleaned_data={})
                authentication_form_clean(form)
                self.assertTrue(clean.called)
                self.assertFalse(logger.called)

    def test_log_entry_is_created_on_login(self):
        form = AuthenticationForm(data={
            "username": "foo",
            "password": "bar",
        })
        self.assertFalse(form.is_valid())
        self.assertTrue(Logger.objects.filter(extra="foo", action=Logger.PASSWORD_ATTEMPT).exists())

    def test_no_log_entry_is_created_for_blank_usernames(self):
        form = AuthenticationForm(data={
            "username": "",
            "password": "bar",
        })
        self.assertFalse(form.is_valid())
        self.assertFalse(Logger.objects.filter(extra="foo", action=Logger.PASSWORD_ATTEMPT).exists())

    def test_multiple_login_attempts(self):
        """
        This is an integration test that runs through all the possible login
        scenarios
        """
        # do too many login attempts
        for i in range(settings.LOGIN_RATE_LIMIT[0]):
            form = AuthenticationForm(data={
                "username": "foo",
                "password": "bar",
            })
            self.assertFalse(form.is_valid())

        # now we should see the Too many login attempts errors
        form = AuthenticationForm(data={
            "username": "foo",
            "password": "bar",
        })
        self.assertFalse(form.is_valid())
        self.assertIn("Too many login attempts", str(form.errors))

        # but if we reset the password...
        user = make(User, username="foo")
        form = SetPasswordForm(user, {"new_password1": "asdfasdf1", "new_password2": "asdfasdf1"})
        self.assertTrue(form.is_valid())
        form.save()

        # ...the Too many logins error should go away
        form = AuthenticationForm(data={
            "username": "foo",
            "password": "bar",
        })
        self.assertFalse(form.is_valid())
        self.assertNotIn("Too many login attempts", str(form.errors))

        # but if we do a bunch of logins again, it should cause a problem
        for i in range(settings.LOGIN_RATE_LIMIT[0]):
            form = AuthenticationForm(data={
                "username": "foo",
                "password": "bar",
            })
            self.assertFalse(form.is_valid())

        form = AuthenticationForm(data={
            "username": "foo",
            "password": "bar",
        })
        self.assertFalse(form.is_valid())
        self.assertIn("Too many login attempts", str(form.errors))

        # but if we wait LOGIN_RATE_LIMIT[1] seconds, it shouldn't be a problem anymore
        time.sleep(settings.LOGIN_RATE_LIMIT[1].total_seconds())
        form = AuthenticationForm(data={
            "username": "foo",
            "password": "bar",
        })
        self.assertFalse(form.is_valid())
        self.assertNotIn("Too many login attempts", str(form.errors))


class StillAliveMiddlewareTest(TestCase):
    def test_unauthenticated_users_just_have_HIPAA_LAST_PING_updated(self):
        # just hitting the middleware without being logged in should just set
        # the HIPAA_LAST_PING session var
        mw = StillAliveMiddleware()
        request = Mock(
            META={},
            user=Mock(is_authenticated=lambda: False),
            session={}
        )
        right_now = 5
        with patch("hipaa.middleware.time.time", return_value=right_now):
            self.assertEqual(None, mw.process_request(request))
        self.assertEqual(right_now, request.session["HIPAA_LAST_PING"])

    def test_HIPAA_LAST_PING_should_be_set_on_the_first_authenticated_request(self):
        # hitting as an authenticated user with no existing HIPAA_LAST_PING
        # should just update that time
        mw = StillAliveMiddleware()
        request = Mock(
            META={},
            user=Mock(is_authenticated=lambda: True),
            session={}
        )
        right_now = 5
        with patch("hipaa.middleware.time.time", return_value=right_now):
            self.assertEqual(None, mw.process_request(request))
        self.assertEqual(right_now, request.session["HIPAA_LAST_PING"])

    def test_ping_for_unauthenticated_users_should_just_return_unauthenticated(self):
        # if the request has the ping header, then the response should just be
        # OK if the user isn't logged in
        mw = StillAliveMiddleware()
        request = Mock(
            META={"HTTP_X_HIPAA_PING": "1"},
            user=Mock(is_authenticated=lambda: False),
            session={}
        )
        right_now = 5
        with patch("hipaa.middleware.time.time", return_value=right_now):
            self.assertEqual("unauthenticated", json.loads(mw.process_request(request).content.decode())['state'])

    def test_authenticated_user_who_hits_the_site_after_AUTOMATIC_LOGOUT_AFTER_should_be_logged_out(self):
        # a logged in user who hits the site after AUTOMATIC_LOGOUT_AFTER
        # seconds should be logged off and sent to the login page
        mw = StillAliveMiddleware()
        request = Mock(
            META={},
            user=Mock(is_authenticated=lambda: True),
            session={"HIPAA_LAST_PING": 0}
        )
        right_now = 1+settings.AUTOMATIC_LOGOUT_AFTER.total_seconds()
        with patch("hipaa.middleware.time.time", return_value=right_now):
            with patch("hipaa.middleware.logout") as logout:
                with patch("hipaa.middleware.messages"):
                    # should redirect to the login page
                    self.assertEqual(None, mw.process_request(request))
                    self.assertTrue(logout.called)

    def test_pings_after_AUTOMATIC_LOGOUT_AFTER_seconds_should_not_return_authenticated(self):
        mw = StillAliveMiddleware()
        request = Mock(
            META={"HTTP_X_HIPAA_PING": "1"},
            user=Mock(is_authenticated=lambda: True),
            session={"HIPAA_LAST_PING": 0}
        )

        def logout(request):
            request.user.is_authenticated = lambda: False

        right_now = 1+settings.AUTOMATIC_LOGOUT_AFTER.total_seconds()
        with patch("hipaa.middleware.time.time", return_value=right_now):
            with patch("hipaa.middleware.logout", side_effect=logout) as logout:
                with patch("hipaa.middleware.messages"):
                    # should redirect to the login page
                    self.assertNotEqual("authenticated", mw.process_request(request).content.decode())
                    self.assertTrue(logout.called)

    def test_pings_before_AUTOMATIC_LOGOUT_AFTER_seconds_should_be_authenticated(self):
        mw = StillAliveMiddleware()
        request = Mock(
            META={"HTTP_X_HIPAA_PING": "1"},
            user=Mock(is_authenticated=lambda: True),
            session={"HIPAA_LAST_PING": 0}
        )
        right_now = settings.AUTOMATIC_LOGOUT_AFTER.total_seconds()-1
        with patch("hipaa.middleware.time.time", return_value=right_now):
            with patch("hipaa.middleware.logout") as logout:
                with patch("hipaa.middleware.messages"):
                    # should redirect to the login page
                    self.assertEqual("authenticated", json.loads(mw.process_request(request).content.decode())['state'])
                    self.assertFalse(logout.called)

    def test_PING_TIMESTAMP_not_updated_when_ping_header_is_not_one(self):
        mw = StillAliveMiddleware()
        request = Mock(
            META={"HTTP_X_HIPAA_PING": "0"},
            user=Mock(is_authenticated=lambda: True),
            session={"HIPAA_LAST_PING": 0}
        )
        right_now = settings.AUTOMATIC_LOGOUT_AFTER.total_seconds()-1
        with patch("hipaa.middleware.time.time", return_value=right_now):
            with patch("hipaa.middleware.logout") as logout:
                with patch("hipaa.middleware.messages"):
                    # should redirect to the login page
                    self.assertEqual("authenticated", json.loads(mw.process_request(request).content.decode())['state'])
                    self.assertFalse(logout.called)
        self.assertEqual(0, request.session["HIPAA_LAST_PING"])

    def test_anonymous_users_dont_ping_very_often(self):
        mw = StillAliveMiddleware()
        request = Mock(
            META={"HTTP_X_HIPAA_PING": "1"},
            user=Mock(is_authenticated=lambda: False),
            session={"HIPAA_LAST_PING": 0}
        )
        right_now = settings.AUTOMATIC_LOGOUT_AFTER.total_seconds()-1
        with patch("hipaa.middleware.time.time", return_value=right_now):
            self.assertEqual(2147483.0, json.loads(mw.process_request(request).content.decode())['seconds_until_next_ping'])

    def test_pings_happen_more_frequently_as_the_logout_time_approaches(self):
        mw = StillAliveMiddleware()
        request = Mock(
            META={"HTTP_X_HIPAA_PING": "1"},
            user=Mock(is_authenticated=lambda: True),
            session={"HIPAA_LAST_PING": 0}
        )
        right_now = 0
        with patch("hipaa.middleware.time.time", return_value=right_now):
            self.assertEqual(2.5, json.loads(mw.process_request(request).content.decode())['seconds_until_next_ping'])

        # if we're 1 second in, the ping should happen at 2 seconds, since
        # we're 4 seconds away from logout
        mw = StillAliveMiddleware()
        request = Mock(
            META={"HTTP_X_HIPAA_PING": "0"},
            user=Mock(is_authenticated=lambda: True),
            session={"HIPAA_LAST_PING": 0}
        )
        right_now = 1
        with patch("hipaa.middleware.time.time", return_value=right_now):
            self.assertEqual(2, json.loads(mw.process_request(request).content.decode())['seconds_until_next_ping'])

        # if we're two seconds in, the ping should happen in 1.5 seconds, since
        # we're 3 seconds away from logout
        mw = StillAliveMiddleware()
        request = Mock(
            META={"HTTP_X_HIPAA_PING": "0"},
            user=Mock(is_authenticated=lambda: True),
            session={"HIPAA_LAST_PING": 0}
        )
        right_now = 2
        with patch("hipaa.middleware.time.time", return_value=right_now):
            self.assertEqual(1.5, json.loads(mw.process_request(request).content.decode())['seconds_until_next_ping'])

        # if we're three seconds in, the ping should happen in 1 seconds, since
        # we're 2 seconds away from logout
        mw = StillAliveMiddleware()
        request = Mock(
            META={"HTTP_X_HIPAA_PING": "0"},
            user=Mock(is_authenticated=lambda: True),
            session={"HIPAA_LAST_PING": 0}
        )
        right_now = 3
        with patch("hipaa.middleware.time.time", return_value=right_now):
            self.assertEqual(1, json.loads(mw.process_request(request).content.decode())['seconds_until_next_ping'])

        # if we're four seconds in, the ping should happen in 1 seconds (not at 0.5 since that is too small), since
        # we're 1 second away from logout
        mw = StillAliveMiddleware()
        request = Mock(
            META={"HTTP_X_HIPAA_PING": "0"},
            user=Mock(is_authenticated=lambda: True),
            session={"HIPAA_LAST_PING": 0}
        )
        right_now = 4
        with patch("hipaa.middleware.time.time", return_value=right_now):
            self.assertEqual(1, json.loads(mw.process_request(request).content.decode())['seconds_until_next_ping'])


class PasswordChangeTest(TestCase):
    def test_password_length_no_less_than_8(self):
        user = make(User, first_name="first", last_name="last", email="me@example.com", username="username")
        form = SetPasswordForm(user=user, data={
            "new_password1": "123",
            "new_password2": "123",
        })
        self.assertFalse(form.is_valid())
        self.assertIn("The password must be 8 characters", str(form.errors['new_password2']))

    def test_password_must_have_one_number(self):
        user = make(User, first_name="first", last_name="last", email="me@example.com", username="username")
        form = SetPasswordForm(user=user, data={
            "new_password1": "abcdefghi",
            "new_password2": "abcdefghi",
        })
        self.assertFalse(form.is_valid())
        self.assertIn("The password must have at least one number", str(form.errors['new_password2']))

    def test_password_must_have_one_letter(self):
        user = make(User, first_name="first", last_name="last", email="me@example.com", username="username")
        form = SetPasswordForm(user=user, data={
            "new_password1": "123456789",
            "new_password2": "123456789"
        })
        self.assertFalse(form.is_valid())
        self.assertIn("The password must have at least one letter", str(form.errors['new_password2']))

    def test_password_must_not_contain_username(self):
        user = make(User, first_name="first", last_name="last", email="me@example.com", username="username")
        form = SetPasswordForm(user=user, data={
            "new_password1": "username1",
            "new_password2": "username1"
        })
        self.assertFalse(form.is_valid())
        self.assertIn("The password must not contain your username/email", str(form.errors['new_password2']))

    def test_password_must_not_contain_email(self):
        user = make(User, first_name="first", last_name="last", email="me@example.com", username="username")
        form = SetPasswordForm(user=user, data={
            "new_password1": "me@example.com1",
            "new_password2": "me@example.com1"
        })
        self.assertFalse(form.is_valid())
        self.assertIn("The password must not contain your username/email", str(form.errors['new_password2']))

    def test_password_must_not_contain_name(self):
        user = make(User, first_name="first", last_name="last", email="me@example.com", username="username")
        form = SetPasswordForm(user=user, data={
            "new_password1": "first1first",
            "new_password2": "first1first"
        })
        self.assertFalse(form.is_valid())
        self.assertIn("The password must not contain your name", str(form.errors['new_password2']))

        form = SetPasswordForm(user=user, data={
            "new_password1": "lastlast1",
            "new_password2": "lastlast1"
        })
        self.assertFalse(form.is_valid())
        self.assertIn("The password must not contain your name", str(form.errors['new_password2']))

    def test_password_must_not_be_common(self):
        user = make(User, first_name="first", last_name="last", email="me@example.com", username="username")
        form = SetPasswordForm(user=user, data={
            "new_password1": "password1",
            "new_password2": "password1"
        })
        self.assertFalse(form.is_valid())
        self.assertIn("The password is too common", str(form.errors['new_password2']))

    def test_cant_use_a_previous_password(self):
        user = make(User, first_name="first", last_name="last", email="foo@example.com", username="username")
        form = SetPasswordForm(user=user, data={
            "new_password1": "alphaBETA1!",
            "new_password2": "alphaBETA1!",
        })
        self.assertTrue(form.is_valid())
        form.save()

        # this should fail, since it's exactly the same password
        form = SetPasswordForm(user=user, data={
            "new_password1": "alphaBETA1!",
            "new_password2": "alphaBETA1!",
        })
        self.assertFalse(form.is_valid())
        self.assertTrue(form.has_error("new_password2", code="password-reuse"))

        # this should not fail, since it is a different password
        form = SetPasswordForm(user=user, data={
            "new_password1": "alphaBETA1!!",
            "new_password2": "alphaBETA1!!",
        })
        self.assertTrue(form.is_valid())



class RequirePasswordChangeMiddlewareTest(TestCase):
    def test_noop_for_anonymous_users(self):
        mw = RequirePasswordChangeMiddleware()
        request = Mock(user=Mock(is_authenticated=lambda *args, **kwargs: False), path="/")
        self.assertEqual(None, mw.process_request(request))

    def test_noop_for_pdx_users(self):
        mw = RequirePasswordChangeMiddleware()
        request = Mock(user=Mock(is_authenticated=lambda *args, **kwargs: True, email="foo@pdx.edu"), path="/")
        self.assertEqual(None, mw.process_request(request))

    def test_redirect_to_password_reset(self):
        # if the user has never set their password, it should redirect
        user = make(User, email="foo@example.com")
        mw = RequirePasswordChangeMiddleware()
        request = Mock(user=user, path="/", client=self.client)
        response = mw.process_request(request)
        self.assertNotEqual(None, response)
        self.assertEqual(response.url, reverse(password_change))

        # if the user has changed their password in the last
        # REQUIRE_PASSWORD_RESET_AFTER units of time, then no redirect
        Logger = get_logger()
        Logger.info(user=user, action=Logger.PASSWORD_RESET)
        Logger.objects.update(created_on=now()-REQUIRE_PASSWORD_RESET_AFTER+timedelta(minutes=1))
        mw = RequirePasswordChangeMiddleware()
        request = Mock(user=user, path="/", client=self.client)
        response = mw.process_request(request)
        self.assertEqual(None, response)

        # if we haven't reset in the last REQUIRE_PASSWORD_RESET_AFTER units of
        # time, then redirect
        Logger.objects.all().delete()
        Logger.info(user=user, action=Logger.PASSWORD_RESET)
        Logger.objects.update(created_on=now()-REQUIRE_PASSWORD_RESET_AFTER-timedelta(minutes=1))
        mw = RequirePasswordChangeMiddleware()
        request = Mock(user=user, path="/", client=self.client)
        response = mw.process_request(request)
        self.assertNotEqual(None, response)
        self.assertEqual(response.url, reverse(password_change))

        # staff members are a special case, and have to reset their passwords
        # after REQUIRE_PASSWORD_RESET_FOR_STAFF_AFTER units of time
        user.is_staff = True
        user.save()
        # if we haven't reset in the last REQUIRE_PASSWORD_RESET_FOR_STAFF_AFTER units of
        # time, then redirect
        Logger.objects.all().delete()
        Logger.info(user=user, action=Logger.PASSWORD_RESET)
        Logger.objects.update(created_on=now()-REQUIRE_PASSWORD_RESET_FOR_STAFF_AFTER-timedelta(minutes=1))
        mw = RequirePasswordChangeMiddleware()
        request = Mock(user=user, path="/", client=self.client)
        response = mw.process_request(request)
        self.assertNotEqual(None, response)
        self.assertEqual(response.url, reverse(password_change))

    def test_logout_always_works(self):
        user = make(User, email="foo@example.com")
        mw = RequirePasswordChangeMiddleware()
        request = Mock(user=user, path="/logout/", client=self.client)
        response = mw.process_request(request)
        self.assertEqual(None, response)
