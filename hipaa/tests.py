import time
from unittest.mock import Mock, patch

from django.conf import settings
from django.contrib.auth.models import User
from django.db import models
from django.test import TestCase
from model_mommy.mommy import make

from .forms import AuthenticationForm, SetPasswordForm, rate_limiting_clean
from .middleware import StillAliveMiddleware
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


class RateLimitingOnLoginTest(TestCase):
    def test_nothing_happens_if_username_is_blank(self):
        with patch("hipaa.forms.clean") as clean:
            logger = Mock()
            with patch("hipaa.forms.get_logger", return_value=logger) as clean:
                form = Mock(cleaned_data={})
                rate_limiting_clean(form)
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
            self.assertEqual("unauthenticated", mw.process_request(request).content.decode())

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
        # if you ping the site after AUTOMATIC_LOGOUT_AFTER then you should be
        # logged out, and the response back should be something other than "ok"
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
        # if you ping the site before AUTOMATIC_LOGOUT_AFTER then the response
        # should be OK
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
                    self.assertEqual("authenticated", mw.process_request(request).content.decode())
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
                    self.assertEqual("authenticated", mw.process_request(request).content.decode())
                    self.assertFalse(logout.called)
        self.assertEqual(0, request.session["HIPAA_LAST_PING"])


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
