# Copyright (C) 2012 Sam Bull (lsb@pocketuniverse.ca)
# Copyright (C) 2011-2012 Yaco Sistemas (http://www.yaco.es)
# Copyright (C) 2010 Lorenzo Gil Sanchez <lorenzo.gil.sanchez@gmail.com>
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

import sys

from django.contrib.auth import get_user_model
from django.contrib.auth.models import User as DjangoUserModel
from django.test import TestCase, override_settings

from djangosaml2.backends import Saml2Backend

User = get_user_model()

if sys.version_info < (3, 4):
    # Monkey-patch TestCase to add the assertLogs method introduced in
    # Python 3.4
    from unittest2.case import _AssertLogsContext

    class LoggerTestCase(TestCase):
        def assertLogs(self, logger=None, level=None):
            return _AssertLogsContext(self, logger, level)

    TestCase = LoggerTestCase


class Saml2BackendTests(TestCase):
    def test_update_user(self):
        # we need a user
        user = User.objects.create(username='john')

        backend = Saml2Backend()

        attribute_mapping = {
            'uid': ('username', ),
            'mail': ('email', ),
            'cn': ('first_name', ),
            'sn': ('last_name', ),
            }
        attributes = {
            'uid': ('john', ),
            'mail': ('john@example.com', ),
            'cn': ('John', ),
            'sn': ('Doe', ),
            }
        backend._update_user(user, attributes, attribute_mapping)
        self.assertEqual(user.email, 'john@example.com')
        self.assertEqual(user.first_name, 'John')
        self.assertEqual(user.last_name, 'Doe')

        attribute_mapping['saml_age'] = ('age', )
        attributes['saml_age'] = ('22', )
        backend._update_user(user, attributes, attribute_mapping)
        self.assertEqual(user.age, '22')

    def test_update_user_callable_attributes(self):
        user = User.objects.create(username='john')

        backend = Saml2Backend()
        attribute_mapping = {
            'uid': ('username', ),
            'mail': ('email', ),
            'cn': ('process_first_name', ),
            'sn': ('last_name', ),
            }
        attributes = {
            'uid': ('john', ),
            'mail': ('john@example.com', ),
            'cn': ('John', ),
            'sn': ('Doe', ),
            }
        backend._update_user(user, attributes, attribute_mapping)
        self.assertEqual(user.email, 'john@example.com')
        self.assertEqual(user.first_name, 'John')
        self.assertEqual(user.last_name, 'Doe')

    def test_update_user_empty_attribute(self):
        user = User.objects.create(username='john', last_name='Smith')

        backend = Saml2Backend()
        attribute_mapping = {
            'uid': ('username', ),
            'mail': ('email', ),
            'cn': ('first_name', ),
            'sn': ('last_name', ),
            }
        attributes = {
            'uid': ('john', ),
            'mail': ('john@example.com', ),
            'cn': ('John', ),
            'sn': (),
            }
        with self.assertLogs('djangosaml2', level='DEBUG') as logs:
            backend._update_user(user, attributes, attribute_mapping)
        self.assertEqual(user.email, 'john@example.com')
        self.assertEqual(user.first_name, 'John')
        # empty attribute list: no update
        self.assertEqual(user.last_name, 'Smith')
        self.assertIn(
            'DEBUG:djangosaml2:Could not find value for "sn", not '
            'updating fields "(\'last_name\',)"',
            logs.output,
        )

    def test_invalid_model_attribute_log(self):
        backend = Saml2Backend()

        attribute_mapping = {
            'uid': ['username'],
            'cn': ['nonexistent'],
        }
        attributes = {
            'uid': ['john'],
            'cn': ['John'],
        }

        with self.assertLogs('djangosaml2', level='DEBUG') as logs:
            backend.get_saml2_user(True, 'john', attributes, attribute_mapping)

        self.assertIn(
            'DEBUG:djangosaml2:Could not find attribute "nonexistent" on user "john"',
            logs.output,
        )

    def test_django_user_main_attribute(self):
        backend = Saml2Backend()

        old_username_field = User.USERNAME_FIELD
        User.USERNAME_FIELD = 'slug'
        self.assertEqual(backend.get_django_user_main_attribute(), 'slug')
        User.USERNAME_FIELD = old_username_field

        with override_settings(AUTH_USER_MODEL='auth.User'):
            self.assertEqual(
                DjangoUserModel.USERNAME_FIELD,
                backend.get_django_user_main_attribute())

        with override_settings(
                AUTH_USER_MODEL='testprofiles.StandaloneUserModel'):
            self.assertEqual(
                backend.get_django_user_main_attribute(),
                'username')

        with override_settings(SAML_DJANGO_USER_MAIN_ATTRIBUTE='foo'):
            self.assertEqual(backend.get_django_user_main_attribute(), 'foo')

    def test_django_user_main_attribute_lookup(self):
        backend = Saml2Backend()

        self.assertEqual(backend.get_django_user_main_attribute_lookup(), '')

        with override_settings(
                SAML_DJANGO_USER_MAIN_ATTRIBUTE_LOOKUP='__iexact'):
            self.assertEqual(
                backend.get_django_user_main_attribute_lookup(),
                '__iexact')


class LowerCaseSaml2Backend(Saml2Backend):
    def clean_attributes(self, attributes):
        return dict([k.lower(), v] for k, v in attributes.items())


class LowerCaseSaml2BackendTest(TestCase):
    def test_update_user_clean_attributes(self):
        user = User.objects.create(username='john')
        attribute_mapping = {
            'uid': ('username', ),
            'mail': ('email', ),
            'cn': ('first_name', ),
            'sn': ('last_name', ),
            }
        attributes = {
            'UID': ['john'],
            'MAIL': ['john@example.com'],
            'CN': ['John'],
            'SN': [],
        }

        backend = LowerCaseSaml2Backend()
        user = backend.authenticate(
            None,
            session_info={'ava': attributes},
            attribute_mapping=attribute_mapping,
        )
        self.assertIsNotNone(user)
