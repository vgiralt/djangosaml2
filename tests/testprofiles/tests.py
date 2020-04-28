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
from django.core.exceptions import ImproperlyConfigured
from djangosaml2.backends import (Saml2Backend, get_model, get_saml_user_model, set_attribute,
                                  get_django_user_lookup_attribute, get_django_user_lookup_attribute,
                                  get_saml_user_model)

from .models import TestUser

User = get_user_model()


class BackendUtilsTests(TestCase):
    def test_get_model_ok(self):
        user_model = get_model('testprofiles.TestUser')
        self.assertEqual(user_model, TestUser)

    def test_get_model_nonexisting(self):
        nonexisting_model = 'testprofiles.NonExisting'

        with self.assertRaisesMessage(ImproperlyConfigured, f"SAML_USER_MODEL refers to model '{nonexisting_model}' that has not been installed"):
            get_model(nonexisting_model)

    def test_get_model_invalid_specifier(self):
        nonexisting_model = 'random_package.specifier.testprofiles.NonExisting'

        with self.assertRaisesMessage(ImproperlyConfigured, "SAML_USER_MODEL must be of the form 'app_label.model_name'"):
            get_model(nonexisting_model)

    def test_get_saml_user_model_specified(self):
        with override_settings(AUTH_USER_MODEL='auth.User'):
            with override_settings(SAML_USER_MODEL='testprofiles.TestUser'):
                self.assertEqual(get_saml_user_model(), TestUser)

    def test_get_saml_user_model_default(self):
        with override_settings(AUTH_USER_MODEL='auth.User'):
            self.assertEqual(get_saml_user_model(), DjangoUserModel)

    def test_get_django_user_lookup_attribute_specified(self):
        with override_settings(SAML_USER_MODEL='testprofiles.TestUser'):
            with override_settings(SAML_DJANGO_USER_MAIN_ATTRIBUTE='age'):
                self.assertEqual(get_django_user_lookup_attribute(TestUser), 'age')

    def test_get_django_user_lookup_attribute_default(self):
        with override_settings(SAML_USER_MODEL='testprofiles.TestUser'):
            self.assertEqual(get_django_user_lookup_attribute(TestUser), 'username')

    def test_set_attribute(self):
        u = TestUser()
        self.assertFalse(hasattr(u, 'custom_attribute'))

        # Set attribute initially
        changed = set_attribute(u, 'custom_attribute', 'value')
        self.assertTrue(changed)
        self.assertEqual(u.custom_attribute, 'value')

        # 'Update' to the same value again
        changed_same = set_attribute(u, 'custom_attribute', 'value')
        self.assertFalse(changed_same)
        self.assertEqual(u.custom_attribute, 'value')

        # Update to a different value
        changed_different = set_attribute(u, 'custom_attribute', 'new_value')
        self.assertTrue(changed_different)
        self.assertEqual(u.custom_attribute, 'new_value')


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
            user, _ = backend.get_or_create_user(get_django_user_lookup_attribute(get_saml_user_model()), 'john', True)
            backend._update_user(user, attributes, attribute_mapping)

        self.assertIn(
            'DEBUG:djangosaml2:Could not find attribute "nonexistent" on user "john"',
            logs.output,
        )

    def test_django_user_main_attribute(self):
        backend = Saml2Backend()

        old_username_field = User.USERNAME_FIELD
        User.USERNAME_FIELD = 'slug'
        self.assertEqual(get_django_user_lookup_attribute(get_saml_user_model()), 'slug')
        User.USERNAME_FIELD = old_username_field

        with override_settings(AUTH_USER_MODEL='auth.User'):
            self.assertEqual(
                DjangoUserModel.USERNAME_FIELD,
                get_django_user_lookup_attribute(get_saml_user_model()))

        with override_settings(
                AUTH_USER_MODEL='testprofiles.StandaloneUserModel'):
            self.assertEqual(
                get_django_user_lookup_attribute(get_saml_user_model()),
                'username')

        with override_settings(SAML_DJANGO_USER_MAIN_ATTRIBUTE='foo'):
            self.assertEqual(get_django_user_lookup_attribute(get_saml_user_model()), 'foo')

    def test_get_or_create_user_existing(self):
        backend = Saml2Backend()

        TestUser.objects.create(username='john')

        with override_settings(SAML_USER_MODEL='testprofiles.TestUser'):
            john, created = backend.get_or_create_user(
                get_django_user_lookup_attribute(get_saml_user_model()),
                'john',
                False,
            )

        self.assertTrue(isinstance(john, TestUser))
        self.assertFalse(created)

    def test_get_or_create_user_duplicates(self):
        backend = Saml2Backend()

        TestUser.objects.create(username='john', age=1)
        TestUser.objects.create(username='paul', age=1)

        with self.assertLogs('djangosaml2', level='DEBUG') as logs:
            with override_settings(SAML_USER_MODEL='testprofiles.TestUser'):
                john, created = backend.get_or_create_user(
                    'age',
                    1,
                    False,
                )

        self.assertTrue(john is None)
        self.assertFalse(created)
        self.assertIn(
            "ERROR:djangosaml2:Multiple users match, model: testprofiles.testuser, lookup: {'age': 1}",
            logs.output,
        )

    def test_get_or_create_user_no_create(self):
        backend = Saml2Backend()

        with self.assertLogs('djangosaml2', level='DEBUG') as logs:
            with override_settings(SAML_USER_MODEL='testprofiles.TestUser'):
                john, created = backend.get_or_create_user(
                    get_django_user_lookup_attribute(get_saml_user_model()),
                    'john',
                    False,
                )

        self.assertTrue(john is None)
        self.assertFalse(created)
        self.assertIn(
            "ERROR:djangosaml2:The user does not exist, model: testprofiles.testuser, lookup: {'username': 'john'}",
            logs.output,
        )

    def test_get_or_create_user_create(self):
        backend = Saml2Backend()

        with self.assertLogs('djangosaml2', level='DEBUG') as logs:
            with override_settings(SAML_USER_MODEL='testprofiles.TestUser'):
                john, created = backend.get_or_create_user(
                    get_django_user_lookup_attribute(get_saml_user_model()),
                    'john',
                    True,
                )

        self.assertTrue(isinstance(john, TestUser))
        self.assertTrue(created)
        self.assertIn(
            f"DEBUG:djangosaml2:New user created: {john}",
            logs.output,
        )


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
