# Copyright (C) 2010-2012 Yaco Sistemas (http://www.yaco.es)
# Copyright (C) 2009 Lorenzo Gil Sanchez <lorenzo.gil.sanchez@gmail.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#            http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging

from django.conf import settings
from django.contrib import auth
from django.contrib.auth.backends import ModelBackend
from django.core.exceptions import (ImproperlyConfigured,
                                    MultipleObjectsReturned)

from .signals import pre_user_save

logger = logging.getLogger('djangosaml2')


def get_model(model_path):
    from django.apps import apps
    try:
        return apps.get_model(model_path)
    except LookupError:
        raise ImproperlyConfigured("SAML_USER_MODEL refers to model '%s' that has not been installed" % model_path)
    except ValueError:
        raise ImproperlyConfigured("SAML_USER_MODEL must be of the form 'app_label.model_name'")


def get_saml_user_model():
    if hasattr(settings, 'SAML_USER_MODEL'):
        return get_model(settings.SAML_USER_MODEL)
    return auth.get_user_model()


def get_django_user_lookup_attribute(userModel):
    if hasattr(settings, 'SAML_DJANGO_USER_MAIN_ATTRIBUTE'):
        return settings.SAML_DJANGO_USER_MAIN_ATTRIBUTE
    return getattr(userModel, 'USERNAME_FIELD', 'username')


def set_attribute(obj, attr, value):
    """ Set an attribute of an object to a specific value, if it wasn't that already.
        Return True if the attribute was changed and False otherwise.
    """

    old_value = getattr(obj, attr)
    if cleaned_value != old_value:
        setattr(obj, attr, cleaned_value)
        return True

    return False


class Saml2Backend(ModelBackend):
    def __init__(self):
        super().__init__()
        self.UserModel = get_saml_user_model()

    def _extract_user_identifier_value(self, session_info, attributes, attribute_mapping):
        """ Extract the user identifier value from the saml attributes.
            Returns None if no identifier could be extracted from the saml payload.
        """
        if getattr(settings, 'SAML_USE_NAME_ID_AS_USERNAME', False):
            if 'name_id' in session_info:
                logger.debug('name_id: %s', session_info['name_id'])
                saml_user_identifier = session_info['name_id'].text
            else:
                logger.error('The nameid is not available. Cannot find user without a nameid.')
                saml_user_identifier = None
        else:
            # Obtain the value of the custom attribute to use
            user_lookup_attribute = get_django_user_lookup_attribute(self.UserModel)
            saml_user_identifier = self._get_attribute_value(user_lookup_attribute, attributes, attribute_mapping)

        return self.clean_user_main_attribute(saml_user_identifier)

    def _get_attribute_value(self, django_field, attributes, attribute_mapping):
        saml_attribute = None
        logger.debug('attribute_mapping: %s', attribute_mapping)
        for saml_attr, django_fields in attribute_mapping.items():
            if django_field in django_fields and saml_attr in attributes:
                saml_attribute = attributes.get(saml_attr, [None])[0]
                if not saml_attribute:
                    logger.error('attributes[saml_attr] attribute '
                                 'value is missing. Probably the user '
                                 'session is expired.')
        return saml_attribute

    def get_or_create_user(self, user_identifier, create_unknown_user, **kwargs):
        """ Look up the user to authenticate. If he doesn't exist, this method creates him (if so desired).
            The default implementation looks only at the user_identifier. Override this method in order to do more complex behaviour,
            e.g. customize this per IdP. The kwargs contain these additional params: session_info, attribute_mapping, attributes, request.
            The identity provider id can be found in kwargs['session_info']['issuer]
        """
        # Construct query parameters to query the userModel with.
        user_lookup_attribute = get_django_user_lookup_attribute(self.UserModel)
        user_query_args = {
            user_lookup_attribute + getattr(settings, 'SAML_DJANGO_USER_MAIN_ATTRIBUTE_LOOKUP', ''): user_identifier
        }

        # Lookup existing user
        user, created = None, False
        try:
            user = self.UserModel.objects.get(**user_query_args)
        except MultipleObjectsReturned:
            logger.error("Multiple users match, lookup: %s", user_query_args)
        except self.UserModel.DoesNotExist:
            logger.error('The user does not exist, lookup: %s', user_query_args)

            # Create new one if desired by settings
            if create_unknown_user:
                try:
                    user, created = self.UserModel.objects.get_or_create(**user_query_args, defaults={user_lookup_attribute: user_identifier})
                except Exception as e:
                    logger.error('Could not create new user: %s', e)

                if created:
                    logger.debug('New user created: %s', user)

        return user, created

    def authenticate(self, request, session_info=None, attribute_mapping=None, create_unknown_user=True, **kwargs):
        if session_info is None or attribute_mapping is None:
            logger.info('Session info or attribute mapping are None')
            return None

        if 'ava' not in session_info:
            logger.error('"ava" key not found in session_info')
            return None

        attributes = self.clean_attributes(session_info['ava'])
        if not attributes:
            logger.error('The (cleaned) attributes dictionary is empty')
            return None
        
        logger.debug('attributes: %s', attributes)

        if not self.is_authorized(attributes, attribute_mapping):
            logger.error('Request not authorized')
            return None

        user_identifier = self._extract_user_identifier_value(session_info, attributes, attribute_mapping)
        if not user_identifier:
            logger.error('Could not determine user identifier')
            return None

        user, created = self.get_or_create_user(
            user_identifier, create_unknown_user,
            request=request, session_info=session_info, attributes=attributes, attribute_mapping=attribute_mapping
        )

        # Update user with new attributes from incoming request
        if user is not None:
            user = self.update_user(user, attributes, attribute_mapping, force_save=created)
            logger.debug('User updated with incoming attributes')

        return user

    def is_authorized(self, attributes, attribute_mapping):
        """Hook to allow custom authorization policies based on
        SAML attributes.
        """
        return True

    def clean_attributes(self, attributes):
        """Hook to clean attributes from the SAML response."""
        return attributes

    def clean_user_main_attribute(self, main_attribute):
        """Performs any cleaning on the user main attribute (which
        usually is "username") prior to using it to get or
        create the user object.  Returns the cleaned attribute.

        By default, returns the attribute unchanged.
        """
        return main_attribute

    def update_user(self, user, attributes, attribute_mapping, force_save=False):
        """Update a user with a set of attributes and returns the updated user.

        By default it uses a mapping defined in the settings constant
        SAML_ATTRIBUTE_MAPPING. For each attribute, if the user object has
        that field defined it will be set.
        """
        if not attribute_mapping:
            return user

        user_modified = False
        for saml_attr, django_attrs in attribute_mapping.items():
            attr_value_list = attributes.get(saml_attr)
            if not attr_value_list:
                logger.debug(
                    'Could not find value for "%s", not updating fields "%s"',
                    saml_attr, django_attrs)
                continue

            for attr in django_attrs:
                if hasattr(user, attr):
                    user_attr = getattr(user, attr)
                    if callable(user_attr):
                        modified = user_attr(attr_value_list)
                    else:
                        modified = set_attribute(user, attr, attr_value_list[0])

                    user_modified = user_modified or modified
                else:
                    logger.debug(
                        'Could not find attribute "%s" on user "%s"', attr, user)

        logger.debug('Sending the pre_save signal')
        signal_modified = any(
            [response for receiver, response
             in pre_user_save.send_robust(sender=user.__class__,
                                          instance=user,
                                          attributes=attributes,
                                          user_modified=user_modified)]
            )

        if user_modified or signal_modified or force_save:
            user.save()

        return user
