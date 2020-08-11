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
import base64
import datetime
import re
import sys
from importlib import import_module
from unittest import mock, skip
from urllib.parse import parse_qs, urlparse

from django.conf import settings
from django.contrib.auth import SESSION_KEY, get_user_model
from django.contrib.auth.models import AnonymousUser
from django.core.exceptions import ImproperlyConfigured
from django.http.request import HttpRequest
from django.template import Context, Template
from django.test import Client, TestCase
from django.test.client import RequestFactory
from django.urls import reverse
from django.utils.encoding import force_text
from djangosaml2 import views
from djangosaml2.cache import OutstandingQueriesCache
from djangosaml2.conf import get_config
from djangosaml2.middleware import SamlSessionMiddleware
from djangosaml2.tests import conf
from djangosaml2.utils import (get_custom_setting,
                               get_idp_sso_supported_bindings,
                               get_session_id_from_saml2,
                               get_subject_id_from_saml2,
                               saml2_from_httpredirect_request)
from djangosaml2.views import finish_logout
from saml2.config import SPConfig
from saml2.s_utils import decode_base64_and_inflate, deflate_and_base64_encode

from .auth_response import auth_response
from .utils import SAMLPostFormParser

User = get_user_model()

PY_VERSION = sys.version_info[:2]


def dummy_loader(request):
    return 'dummy_loader'


non_callable = 'just a string'


class UtilsTests(TestCase):
    def test_get_config_valid_path(self):
        self.assertEqual(get_config('djangosaml2.tests.dummy_loader'), 'dummy_loader')

    def test_get_config_wrongly_formatted_path(self):
        with self.assertRaisesMessage(ImproperlyConfigured, 'SAML config loader must be a callable object.'):
            get_config('djangosaml2.tests.non_callable')

    def test_get_config_nonsense_path(self):
        with self.assertRaisesMessage(ImproperlyConfigured, 'Error importing SAML config loader lalala.nonexisting.blabla: "No module named \'lalala\'"'):
            get_config('lalala.nonexisting.blabla')

    def test_get_config_missing_function(self):
        with self.assertRaisesMessage(ImproperlyConfigured, 'Module "djangosaml2.tests" does not define a "nonexisting_function" attribute/class'):
            get_config('djangosaml2.tests.nonexisting_function')


class SAML2Tests(TestCase):

    urls = 'djangosaml2.tests.urls'

    def setUp(self):
        if hasattr(settings, 'SAML_ATTRIBUTE_MAPPING'):
            self.actual_attribute_mapping = settings.SAML_ATTRIBUTE_MAPPING
            del settings.SAML_ATTRIBUTE_MAPPING
        if hasattr(settings, 'SAML_CONFIG_LOADER'):
            self.actual_conf_loader = settings.SAML_CONFIG_LOADER
            del settings.SAML_CONFIG_LOADER

    def tearDown(self):
        if hasattr(self, 'actual_attribute_mapping'):
            settings.SAML_ATTRIBUTE_MAPPING = self.actual_attribute_mapping
        if hasattr(self, 'actual_conf_loader'):
            settings.SAML_CONFIG_LOADER = self.actual_conf_loader

    def assertSAMLRequestsEquals(self, real_xml, expected_xmls):

        def remove_variable_attributes(xml_string):
            xml_string = re.sub(r' ID=".*?" ', ' ', xml_string)
            xml_string = re.sub(r' IssueInstant=".*?" ', ' ', xml_string)
            xml_string = re.sub(
                r'<saml:NameID(.*)>.*</saml:NameID>',
                r'<saml:NameID\1></saml:NameID>',
                xml_string)

            return xml_string

        self.assertEqual(remove_variable_attributes(real_xml),
                         remove_variable_attributes(expected_xmls))

    def init_cookies(self):
        self.client.cookies[settings.SESSION_COOKIE_NAME] = 'testing'

    def add_outstanding_query(self, session_id, came_from):
        settings.SESSION_ENGINE = 'django.contrib.sessions.backends.db'
        engine = import_module(settings.SESSION_ENGINE)
        self.saml_session = engine.SessionStore()
        self.saml_session.save()
        self.oq_cache = OutstandingQueriesCache(self.saml_session)

        self.oq_cache.set(session_id \
                          if isinstance(session_id, str) else session_id.decode(),
                          came_from)
        self.saml_session.save()
        self.client.cookies[settings.SESSION_COOKIE_NAME] = self.saml_session.session_key

    def render_template(self, text):
        return Template(text).render(Context())

    def b64_for_post(self, xml_text, encoding='utf-8'):
        return base64.b64encode(xml_text.encode(encoding)).decode('ascii')

    def test_get_idp_sso_supported_bindings_noargs(self):
        settings.SAML_CONFIG = conf.create_conf(
            sp_host='sp.example.com',
            idp_hosts=['idp.example.com'],
            metadata_file='remote_metadata_one_idp.xml',
        )
        idp_id = 'https://idp.example.com/simplesaml/saml2/idp/metadata.php'
        self.assertEqual(get_idp_sso_supported_bindings()[0], list(settings.SAML_CONFIG['service']['sp']['idp'][idp_id]['single_sign_on_service'].keys())[0])

    def test_get_idp_sso_supported_bindings_unknown_idp(self):
        settings.SAML_CONFIG = conf.create_conf(
            sp_host='sp.example.com',
            idp_hosts=['idp.example.com'],
            metadata_file='remote_metadata_one_idp.xml',
        )
        self.assertEqual(get_idp_sso_supported_bindings(idp_entity_id='random'), [])

    def test_get_idp_sso_supported_bindings_no_idps(self):
        settings.SAML_CONFIG = conf.create_conf(
            sp_host='sp.example.com',
            idp_hosts=[],
            metadata_file='remote_metadata_no_idp.xml',
        )
        with self.assertRaisesMessage(ImproperlyConfigured, "No IdP configured!"):
            get_idp_sso_supported_bindings()

    def test_unsigned_post_authn_request(self):
        """
        Test that unsigned authentication requests via POST binding
        does not error.

        https://github.com/knaperek/djangosaml2/issues/168
        """
        settings.SAML_CONFIG = conf.create_conf(
            sp_host='sp.example.com',
            idp_hosts=['idp.example.com'],
            metadata_file='remote_metadata_post_binding.xml',
            authn_requests_signed=False
        )
        response = self.client.get(reverse('saml2_login'))

        self.assertEqual(response.status_code, 200)

        # Using POST-binding returns a page with form containing the SAMLRequest
        response_parser = SAMLPostFormParser()
        response_parser.feed(response.content.decode('utf-8'))
        saml_request = response_parser.saml_request_value

        self.assertIsNotNone(saml_request)
        if 'AuthnRequest xmlns' not in base64.b64decode(saml_request).decode('utf-8'):
            raise Exception('test_unsigned_post_authn_request: Not a valid AuthnRequest')

    def test_login_evil_redirect(self):
        """
        Make sure that if we give an URL other than our own host as the next
        parameter, it is replaced with the default LOGIN_REDIRECT_URL.
        """

        # monkey patch SAML configuration
        settings.SAML_CONFIG = conf.create_conf(
            sp_host='sp.example.com',
            idp_hosts=['idp.example.com'],
            metadata_file='remote_metadata_one_idp.xml',
        )
        response = self.client.get(reverse('saml2_login') + '?next=http://evil.com')
        url = urlparse(response['Location'])
        params = parse_qs(url.query)

        self.assertEqual(params['RelayState'], [settings.LOGIN_REDIRECT_URL, ])

    def test_no_redirect(self):
        """
        Make sure that if we give an empty path as the next parameter,
        it is replaced with the default LOGIN_REDIRECT_URL.
        """

        # monkey patch SAML configuration
        settings.SAML_CONFIG = conf.create_conf(
            sp_host='sp.example.com',
            idp_hosts=['idp.example.com'],
            metadata_file='remote_metadata_one_idp.xml',
        )
        response = self.client.get(reverse('saml2_login') + '?next=')
        url = urlparse(response['Location'])
        params = parse_qs(url.query)

        self.assertEqual(params['RelayState'], [settings.LOGIN_REDIRECT_URL, ])

    def test_login_one_idp(self):
        # monkey patch SAML configuration
        settings.SAML_CONFIG = conf.create_conf(
            sp_host='sp.example.com',
            idp_hosts=['idp.example.com'],
            metadata_file='remote_metadata_one_idp.xml',
        )

        response = self.client.get(reverse('saml2_login'))
        self.assertEqual(response.status_code, 302)
        location = response['Location']

        url = urlparse(location)
        self.assertEqual(url.hostname, 'idp.example.com')
        self.assertEqual(url.path, '/simplesaml/saml2/idp/SSOService.php')

        params = parse_qs(url.query)
        self.assertIn('SAMLRequest', params)
        self.assertIn('RelayState', params)

        saml_request = params['SAMLRequest'][0]
        if 'AuthnRequest xmlns' not in decode_base64_and_inflate(saml_request).decode('utf-8'):
            raise Exception('Not a valid AuthnRequest')

        # if we set a next arg in the login view, it is preserverd
        # in the RelayState argument
        nexturl = '/another-view/'
        response = self.client.get(reverse('saml2_login'), {'next': nexturl})
        self.assertEqual(response.status_code, 302)
        location = response['Location']

        url = urlparse(location)
        self.assertEqual(url.hostname, 'idp.example.com')
        self.assertEqual(url.path, '/simplesaml/saml2/idp/SSOService.php')

        params = parse_qs(url.query)
        self.assertIn('SAMLRequest', params)
        self.assertIn('RelayState', params)
        self.assertEqual(params['RelayState'][0], nexturl)

    def test_login_several_idps(self):
        settings.SAML_CONFIG = conf.create_conf(
            sp_host='sp.example.com',
            idp_hosts=['idp1.example.com',
                       'idp2.example.com',
                       'idp3.example.com'],
            metadata_file='remote_metadata_three_idps.xml',
        )
        response = self.client.get(reverse('saml2_login'))
        # a WAYF page should be displayed
        self.assertContains(response, 'Where are you from?', status_code=200)
        for i in range(1, 4):
            link = '/login/?idp=https://idp%d.example.com/simplesaml/saml2/idp/metadata.php&next=/'
            self.assertContains(response, link % i)

        # click on the second idp
        response = self.client.get(reverse('saml2_login'), {
                'idp': 'https://idp2.example.com/simplesaml/saml2/idp/metadata.php',
                'next': '/',
                })
        self.assertEqual(response.status_code, 302)
        location = response['Location']

        url = urlparse(location)
        self.assertEqual(url.hostname, 'idp2.example.com')
        self.assertEqual(url.path, '/simplesaml/saml2/idp/SSOService.php')

        params = parse_qs(url.query)
        self.assertIn('SAMLRequest', params)
        self.assertIn('RelayState', params)

        saml_request = params['SAMLRequest'][0]
        if 'AuthnRequest xmlns' not in decode_base64_and_inflate(saml_request).decode('utf-8'):
            raise Exception('Not a valid AuthnRequest')

    def test_assertion_consumer_service(self):
        # Get initial number of users
        initial_user_count = User.objects.count()
        settings.SAML_CONFIG = conf.create_conf(
            sp_host='sp.example.com',
            idp_hosts=['idp.example.com'],
            metadata_file='remote_metadata_one_idp.xml',
        )
        response = self.client.get(reverse('saml2_login'))
        saml2_req = saml2_from_httpredirect_request(response.url)
        session_id = get_session_id_from_saml2(saml2_req)
        # session_id should start with a letter since it is a NCName
        came_from = '/another-view/'
        self.add_outstanding_query(session_id, came_from)

        # this will create a user
        saml_response = auth_response(session_id, 'student')
        _url = reverse('saml2_acs')
        response = self.client.post(_url, {
                'SAMLResponse': self.b64_for_post(saml_response),
                'RelayState': came_from,
                })
        self.assertEqual(response.status_code, 302)
        location = response['Location']
        url = urlparse(location)
        self.assertEqual(url.path, came_from)

        self.assertEqual(User.objects.count(), initial_user_count + 1)
        user_id = self.client.session[SESSION_KEY]
        user = User.objects.get(id=user_id)
        self.assertEqual(user.username, 'student')

        # let's create another user and log in with that one
        new_user = User.objects.create(username='teacher', password='not-used')

        #  session_id = "a1111111111111111111111111111111"
        client = Client()
        response = client.get(reverse('saml2_login'))
        saml2_req = saml2_from_httpredirect_request(response.url)
        session_id = get_session_id_from_saml2(saml2_req)

        came_from = ''  # bad, let's see if we can deal with this
        saml_response = auth_response(session_id, 'teacher')
        self.add_outstanding_query(session_id, '/')
        response = client.post(reverse('saml2_acs'), {
                'SAMLResponse': self.b64_for_post(saml_response),
                'RelayState': came_from,
                })
        self.assertEqual(response.status_code, 302)
        location = response['Location']

        url = urlparse(location)
        # as the RelayState is empty we have redirect to LOGIN_REDIRECT_URL
        self.assertEqual(url.path, settings.LOGIN_REDIRECT_URL)
        self.assertEqual(force_text(new_user.id), client.session[SESSION_KEY])

    def test_assertion_consumer_service_already_logged_in_allowed(self):
        self.client.force_login(User.objects.create(username='user', password='pass'))

        settings.SAML_IGNORE_AUTHENTICATED_USERS_ON_LOGIN = True

        came_from = '/dummy-url/'
        response = self.client.get(reverse('saml2_login') + f'?next={came_from}')
        self.assertEqual(response.status_code, 302)
        url = urlparse(response['Location'])
        self.assertEqual(url.path, came_from)

    def test_assertion_consumer_service_already_logged_in_error(self):
        self.client.force_login(User.objects.create(username='user', password='pass'))

        settings.SAML_IGNORE_AUTHENTICATED_USERS_ON_LOGIN = False

        came_from = '/dummy-url/'
        response = self.client.get(reverse('saml2_login') + f'?next={came_from}')
        self.assertEqual(response.status_code, 200)
        self.assertInHTML("<p>You are already logged in and you are trying to go to the login page again.</p>", response.content.decode())

    def test_assertion_consumer_service_no_session(self):
        settings.SAML_CONFIG = conf.create_conf(
            sp_host='sp.example.com',
            idp_hosts=['idp.example.com'],
            metadata_file='remote_metadata_one_idp.xml',
        )

        response = self.client.get(reverse('saml2_login'))
        saml2_req = saml2_from_httpredirect_request(response.url)
        session_id = get_session_id_from_saml2(saml2_req)
        # session_id should start with a letter since it is a NCName

        came_from = '/another-view/'
        self.add_outstanding_query(session_id, came_from)

        # Authentication is confirmed.
        saml_response = auth_response(session_id, 'student')
        response = self.client.post(reverse('saml2_acs'), {
            'SAMLResponse': self.b64_for_post(saml_response),
            'RelayState': came_from,
        })
        self.assertEqual(response.status_code, 302)
        location = response['Location']
        url = urlparse(location)
        self.assertEqual(url.path, came_from)

        # Session should no longer be in outstanding queries.
        saml_response = auth_response(session_id, 'student')
        response = self.client.post(reverse('saml2_acs'), {
            'SAMLResponse': self.b64_for_post(saml_response),
            'RelayState': came_from,
        })
        self.assertEqual(response.status_code, 403)

    def test_missing_param_to_assertion_consumer_service_request(self):
        # Send request without SAML2Response parameter
        response = self.client.post(reverse('saml2_acs'))
        # Assert that view responded with "Bad Request" error
        self.assertEqual(response.status_code, 400)

    def test_bad_request_method_to_assertion_consumer_service(self):
        # Send request with non-POST method.
        response = self.client.get(reverse('saml2_acs'))
        # Assert that view responded with method not allowed status
        self.assertEqual(response.status_code, 405)

    def do_login(self):
        """Auxiliary method used in several tests (mainly logout tests)"""
        self.init_cookies()

        response = self.client.get(reverse('saml2_login'))
        saml2_req = saml2_from_httpredirect_request(response.url)
        session_id = get_session_id_from_saml2(saml2_req)
        # session_id should start with a letter since it is a NCName
        came_from = '/another-view/'
        self.add_outstanding_query(session_id, came_from)

        saml_response = auth_response(session_id, 'student')

        # this will create a user
        response = self.client.post(reverse('saml2_acs'), {
                'SAMLResponse': self.b64_for_post(saml_response),
                'RelayState': came_from,
                })
        subject_id = get_subject_id_from_saml2(saml_response)
        self.assertEqual(response.status_code, 302)
        return subject_id

    @skip("This is a known issue caused by pysaml2. Needs more investigation. Fixes are welcome.")
    def test_logout(self):
        settings.SAML_CONFIG = conf.create_conf(
            sp_host='sp.example.com',
            idp_hosts=['idp.example.com'],
            metadata_file='remote_metadata_one_idp.xml',
        )
        self.do_login()

        response = self.client.get(reverse('saml2_logout'))
        self.assertEqual(response.status_code, 302)
        location = response['Location']

        url = urlparse(location)
        self.assertEqual(url.hostname, 'idp.example.com')
        self.assertEqual(url.path,
                         '/simplesaml/saml2/idp/SingleLogoutService.php')

        params = parse_qs(url.query)
        self.assertIn('SAMLRequest', params)

        saml_request = params['SAMLRequest'][0]

        if 'LogoutRequest xmlns' not in decode_base64_and_inflate(saml_request).decode('utf-8'):
            raise Exception('Not a valid LogoutRequest')



    def test_logout_service_local(self):
        settings.SAML_CONFIG = conf.create_conf(
            sp_host='sp.example.com',
            idp_hosts=['idp.example.com'],
            metadata_file='remote_metadata_one_idp.xml',
        )

        self.do_login()

        response = self.client.get(reverse('saml2_logout'))
        self.assertEqual(response.status_code, 302)
        location = response['Location']

        url = urlparse(location)
        self.assertEqual(url.hostname, 'idp.example.com')
        self.assertEqual(url.path,
                         '/simplesaml/saml2/idp/SingleLogoutService.php')

        params = parse_qs(url.query)
        self.assertIn('SAMLRequest', params)

        saml_request = params['SAMLRequest'][0]
        if 'LogoutRequest xmlns' not in decode_base64_and_inflate(saml_request).decode('utf-8'):
            raise Exception('Not a valid LogoutRequest')

        # now simulate a logout response sent by the idp
        expected_request = """<samlp:LogoutRequest xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="XXXXXXXXXXXXXXXXXXXXXX" Version="2.0" Destination="https://idp.example.com/simplesaml/saml2/idp/SingleLogoutService.php" Reason=""><saml:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">http://sp.example.com/saml2/metadata/</saml:Issuer><saml:NameID SPNameQualifier="http://sp.example.com/saml2/metadata/" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">1f87035b4c1325b296a53d92097e6b3fa36d7e30ee82e3fcb0680d60243c1f03</saml:NameID><samlp:SessionIndex>a0123456789abcdef0123456789abcdef</samlp:SessionIndex></samlp:LogoutRequest>"""

        request_id = re.findall(r' ID="(.*?)" ', expected_request)[0]
        instant = datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%SZ')

        saml_response = """<?xml version='1.0' encoding='UTF-8'?>
<samlp:LogoutResponse xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" Destination="http://sp.example.com/saml2/ls/" ID="a140848e7ce2bce834d7264ecdde0151" InResponseTo="%s" IssueInstant="%s" Version="2.0"><saml:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">https://idp.example.com/simplesaml/saml2/idp/metadata.php</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" /></samlp:Status></samlp:LogoutResponse>""" % (
            request_id, instant)

        response = self.client.get(reverse('saml2_ls'), {
                'SAMLResponse': deflate_and_base64_encode(saml_response),
                })
        self.assertContains(response, "Logged out", status_code=200)
        self.assertListEqual(list(self.client.session.keys()), [])

    def test_logout_service_global(self):
        settings.SAML_CONFIG = conf.create_conf(
            sp_host='sp.example.com',
            idp_hosts=['idp.example.com'],
            metadata_file='remote_metadata_one_idp.xml',
        )

        subject_id = self.do_login()
        # now simulate a global logout process initiated by another SP
        subject_id = views._get_subject_id(self.saml_session)
        instant = datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%SZ')
        saml_request = """<?xml version='1.0' encoding='UTF-8'?>
<samlp:LogoutRequest xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_9961abbaae6d06d251226cb25e38bf8f468036e57e" Version="2.0" IssueInstant="%s" Destination="http://sp.example.com/saml2/ls/"><saml:Issuer>https://idp.example.com/simplesaml/saml2/idp/metadata.php</saml:Issuer><saml:NameID SPNameQualifier="http://sp.example.com/saml2/metadata/" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">%s</saml:NameID><samlp:SessionIndex>_1837687b7bc9faad85839dbeb319627889f3021757</samlp:SessionIndex></samlp:LogoutRequest>""" % (instant, subject_id)

        response = self.client.get(reverse('saml2_ls'), {
                'SAMLRequest': deflate_and_base64_encode(saml_request),
                })
        self.assertEqual(response.status_code, 302)
        location = response['Location']

        url = urlparse(location)
        self.assertEqual(url.hostname, 'idp.example.com')
        self.assertEqual(url.path,
                         '/simplesaml/saml2/idp/SingleLogoutService.php')

        params = parse_qs(url.query)
        self.assertIn('SAMLResponse', params)
        saml_response = params['SAMLResponse'][0]

        if 'Response xmlns' not in decode_base64_and_inflate(saml_response).decode('utf-8'):
            raise Exception('Not a valid Response')

    def test_incomplete_logout(self):
        settings.SAML_CONFIG = conf.create_conf(sp_host='sp.example.com',
                                                idp_hosts=['idp.example.com'])

        # don't do a login

        # now simulate a global logout process initiated by another SP
        instant = datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%SZ')
        saml_request = '<samlp:LogoutRequest xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_9961abbaae6d06d251226cb25e38bf8f468036e57e" Version="2.0" IssueInstant="%s" Destination="http://sp.example.com/saml2/ls/"><saml:Issuer>https://idp.example.com/simplesaml/saml2/idp/metadata.php</saml:Issuer><saml:NameID SPNameQualifier="http://sp.example.com/saml2/metadata/" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">%s</saml:NameID><samlp:SessionIndex>_1837687b7bc9faad85839dbeb319627889f3021757</samlp:SessionIndex></samlp:LogoutRequest>' % (
            instant, 'invalid-subject-id')

        response = self.client.get(reverse('saml2_ls'), {
                'SAMLRequest': deflate_and_base64_encode(saml_request),
                })
        self.assertContains(response, 'Logout error', status_code=403)

    def test_finish_logout_renders_error_template(self):
        request = RequestFactory().get('/bar/foo')
        response = finish_logout(request, None)
        self.assertContains(response, "<h1>Logout error</h1>", status_code=200)

    def _test_metadata(self):
        settings.SAML_CONFIG = conf.create_conf(
            sp_host='sp.example.com',
            idp_hosts=['idp.example.com'],
            metadata_file='remote_metadata_one_idp.xml',
        )
        valid_until = datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        valid_until = valid_until.strftime("%Y-%m-%dT%H:%M:%SZ")
        expected_metadata = """<?xml version='1.0' encoding='UTF-8'?>
<md:EntityDescriptor entityID="http://sp.example.com/saml2/metadata/" validUntil="%s" xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"><md:SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><md:KeyDescriptor><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>MIIDPjCCAiYCCQCkHjPQlll+mzANBgkqhkiG9w0BAQUFADBhMQswCQYDVQQGEwJF
UzEQMA4GA1UECBMHU2V2aWxsYTEbMBkGA1UEChMSWWFjbyBTaXN0ZW1hcyBTLkwu
MRAwDgYDVQQHEwdTZXZpbGxhMREwDwYDVQQDEwh0aWNvdGljbzAeFw0wOTEyMDQx
OTQzNTJaFw0xMDEyMDQxOTQzNTJaMGExCzAJBgNVBAYTAkVTMRAwDgYDVQQIEwdT
ZXZpbGxhMRswGQYDVQQKExJZYWNvIFNpc3RlbWFzIFMuTC4xEDAOBgNVBAcTB1Nl
dmlsbGExETAPBgNVBAMTCHRpY290aWNvMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
MIIBCgKCAQEA7rMOMOaIZ/YYD5hYS6Hpjpovcu4k8gaIY+om9zCxLV5F8BLEfkxo
Pk9IA3cRQNRxf7AXCFxEOH3nKy56AIi1gU7X6fCT30JBT8NQlYdgOVMLlR+tjy1b
YV07tDa9U8gzjTyKQHgVwH0436+rmSPnacGj3fMwfySTMhtmrJmax0bIa8EB+gY1
77DBtvf8dIZIXLlGMQFloZeUspvHOrgNoEA9xU4E9AanGnV9HeV37zv3mLDUOQLx
4tk9sMQmylCpij7WZmcOV07DyJ/cEmnvHSalBTcyIgkcwlhmjtSgfCy6o5zuWxYd
T9ia80SZbWzn8N6B0q+nq23+Oee9H0lvcwIDAQABMA0GCSqGSIb3DQEBBQUAA4IB
AQCQBhKOqucJZAqGHx4ybDXNzpPethszonLNVg5deISSpWagy55KlGCi5laio/xq
hHRx18eTzeCeLHQYvTQxw0IjZOezJ1X30DD9lEqPr6C+IrmZc6bn/pF76xsvdaRS
gduNQPT1B25SV2HrEmbf8wafSlRARmBsyUHh860TqX7yFVjhYIAUF/El9rLca51j
ljCIqqvT+klPdjQoZwODWPFHgute2oNRmoIcMjSnoy1+mxOC2Q/j7kcD8/etulg2
XDxB3zD81gfdtT8VBFP+G4UrBa+5zFk6fT6U8a7ZqVsyH+rCXAdCyVlEC4Y5fZri
ID4zT0FcZASGuthM56rRJJSx
</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="http://sp.example.com/saml2/ls/" /><md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="http://sp.example.com/saml2/acs/" index="1" /><md:AttributeConsumingService index="1"><md:ServiceName xml:lang="en">Test SP</md:ServiceName><md:RequestedAttribute FriendlyName="uid" Name="urn:oid:0.9.2342.19200300.100.1.1" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true" /><md:RequestedAttribute FriendlyName="eduPersonAffiliation" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.1" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="false" /></md:AttributeConsumingService></md:SPSSODescriptor><md:Organization><md:OrganizationName xml:lang="es">Ejemplo S.A.</md:OrganizationName><md:OrganizationName xml:lang="en">Example Inc.</md:OrganizationName><md:OrganizationDisplayName xml:lang="es">Ejemplo</md:OrganizationDisplayName><md:OrganizationDisplayName xml:lang="en">Example</md:OrganizationDisplayName><md:OrganizationURL xml:lang="es">http://www.example.es</md:OrganizationURL><md:OrganizationURL xml:lang="en">http://www.example.com</md:OrganizationURL></md:Organization><md:ContactPerson contactType="technical"><md:Company>Example Inc.</md:Company><md:GivenName>Technical givenname</md:GivenName><md:SurName>Technical surname</md:SurName><md:EmailAddress>technical@sp.example.com</md:EmailAddress></md:ContactPerson><md:ContactPerson contactType="administrative"><md:Company>Example Inc.</md:Company><md:GivenName>Administrative givenname</md:GivenName><md:SurName>Administrative surname</md:SurName><md:EmailAddress>administrative@sp.example.ccom</md:EmailAddress></md:ContactPerson></md:EntityDescriptor>"""

        expected_metadata = expected_metadata % valid_until

        response = self.client.get(reverse('saml2_metadata'))
        self.assertEqual(response['Content-type'], 'text/xml; charset=utf8')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, expected_metadata)

    def test_sigalg_not_passed_when_not_signing_request(self):
        # monkey patch SAML configuration
        settings.SAML_CONFIG = conf.create_conf(
            sp_host='sp.example.com',
            idp_hosts=['idp.example.com'],
            metadata_file='remote_metadata_one_idp.xml',
        )

        with mock.patch(
            'djangosaml2.views.Saml2Client.prepare_for_authenticate',
            return_value=('session_id', {'url': 'fake'}),

        ) as prepare_for_auth_mock:
            self.client.get(reverse('saml2_login'))
        prepare_for_auth_mock.assert_called_once()
        _args, kwargs = prepare_for_auth_mock.call_args
        self.assertNotIn('sigalg', kwargs)

    def test_sigalg_passed_when_signing_request(self):
        # monkey patch SAML configuration
        settings.SAML_CONFIG = conf.create_conf(
            sp_host='sp.example.com',
            idp_hosts=['idp.example.com'],
            metadata_file='remote_metadata_one_idp.xml',
        )

        settings.SAML_CONFIG['service']['sp']['authn_requests_signed'] = True
        with mock.patch(
            'djangosaml2.views.Saml2Client.prepare_for_authenticate',
            return_value=('session_id', {'url': 'fake'}),

        ) as prepare_for_auth_mock:
            self.client.get(reverse('saml2_login'))
        prepare_for_auth_mock.assert_called_once()
        _args, kwargs = prepare_for_auth_mock.call_args
        self.assertIn('sigalg', kwargs)


def test_config_loader(request):
    config = SPConfig()
    config.load({'entityid': 'testentity'})
    return config


def test_config_loader_callable(request):
    config = SPConfig()
    config.load({'entityid': 'testentity_callable'})
    return config


def test_config_loader_with_real_conf(request):
    config = SPConfig()
    config.load(conf.create_conf(sp_host='sp.example.com',
                                 idp_hosts=['idp.example.com'],
                                 metadata_file='remote_metadata_one_idp.xml'))
    return config


class ConfTests(TestCase):

    def test_custom_conf_loader(self):
        config_loader_path = 'djangosaml2.tests.test_config_loader'
        request = RequestFactory().get('/bar/foo')
        conf = get_config(config_loader_path, request)

        self.assertEqual(conf.entityid, 'testentity')

    def test_custom_conf_loader_callable(self):
        config_loader_path = test_config_loader_callable
        request = RequestFactory().get('/bar/foo')
        conf = get_config(config_loader_path, request)

        self.assertEqual(conf.entityid, 'testentity_callable')

    def test_custom_conf_loader_from_view(self):
        config_loader_path = 'djangosaml2.tests.test_config_loader_with_real_conf'
        request = RequestFactory().get('/login/')
        request.user = AnonymousUser()
        middleware = SamlSessionMiddleware()
        middleware.process_request(request)

        saml_session_name = getattr(settings, 'SAML_SESSION_COOKIE_NAME', 'saml_session')
        getattr(request, saml_session_name).save()

        response = views.LoginView.as_view(config_loader_path=config_loader_path)(request)
        self.assertEqual(response.status_code, 302)
        location = response['Location']

        url = urlparse(location)
        self.assertEqual(url.hostname, 'idp.example.com')
        self.assertEqual(url.path, '/simplesaml/saml2/idp/SSOService.php')
