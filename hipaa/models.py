from django.conf import settings
from django.db import models
from ipware.ip import get_real_ip


class LogModelField(models.ForeignKey):
    def __init__(self, to, to_field=None, related_name="+", related_query_name=None,
                 limit_choices_to=None, parent_link=False, on_delete=models.SET_NULL,
                 db_constraint=True, null=True, **kwargs):
        super(LogModelField, self).__init__(to, to_field=to_field, related_name=related_name, related_query_name=related_query_name,
                                            limit_choices_to=limit_choices_to, parent_link=parent_link, on_delete=on_delete,
                                            db_constraint=db_constraint, null=null, **kwargs)

    def contribute_to_class(self, cls, name, *args, **kwargs):
        super(LogModelField, self).contribute_to_class(cls, name, *args, **kwargs)
        # when a model is deleted, the Foreign Key to it on the Log model will
        # be nulled out. To preserve some historical information, we add
        # another field to the Log model that stores the PK of the field.
        if not cls._meta.abstract:
            model_pk_field = models.CharField(max_length=255, null=True, default=None)
            model_pk_field.contribute_to_class(cls, name + "_pk", *args, **kwargs)


class Log(models.Model):
    CREATED = "created"
    EDITED = "edited"
    DELETED = "deleted"
    VIEWED = "viewed"
    PASSWORD_ATTEMPT = "password_attempt"
    PASSWORD_RESET = "password_reset"

    log_id = models.AutoField(primary_key=True)
    user = LogModelField(settings.AUTH_USER_MODEL, default=None, null=True)
    created_on = models.DateTimeField(auto_now_add=True)
    action = models.CharField(max_length=255)
    level = models.CharField(max_length=255)
    extra = models.TextField()
    ip_address = models.GenericIPAddressField(null=True, default=None)

    # foreign keys to all objects

    class Meta:
        abstract = True

    @classmethod
    def log(cls, level, request=None, action="", extra="", user=None, ip_address=None, **loggable_model_fields):
        if request and request.user.is_authenticated():
            user = request.user

        if request and ip_address is None:
            ip_address = get_real_ip(request)

        if not action:
            raise ValueError("Action must be a non-empty string")

        log = cls(level=level, user=user, user_pk=getattr(user, "pk", ""), action=action, extra=extra, ip_address=ip_address)
        for field_name, model in loggable_model_fields.items():
            setattr(log, field_name, model)
            setattr(log, field_name + "_pk", model.pk)

        log.save()
        return log

    @classmethod
    def info(cls, *args, **kwargs):
        return cls.log("info", *args, **kwargs)

    @classmethod
    def warning(cls, *args, **kwargs):
        return cls.log("warning", *args, **kwargs)

    @classmethod
    def error(cls, *args, **kwargs):
        return cls.log("error", *args, **kwargs)

    @classmethod
    def critical(cls, *args, **kwargs):
        return cls.log("critical", *args, **kwargs)
