# coding=utf-8
import unittest
import sys
import os
import re
import json
import time
import logging
import shutil
import threading
import requests

sys.path.append(os.path.join("..", "src", "bin"))
from webhook import WebServer

sys.path.append(os.path.join("lib"))
import HtmlTestRunner

class WebhooksAppTest(object):
    """
    This provides some functionality for testing the webhooks app, including:

     1) Running the Webhooks web-server (loading the port information from local.properties for
        environmental variables)
     2) Caching the list of results that were received (so that test cases can verify them)
    """

    DEFAULT_TEST_SERVER_PORT = 28080
    config_loaded = False
    port = DEFAULT_TEST_SERVER_PORT

    httpd = None
    thread = None
    path = '/test_run_webserver'
    results = None
    protocol = 'http'

    def toInt(self, str_int):
        """
        Convert the string to an integer but return None if the value is None.
        """

        if str_int is None:
            return None
        else:
            return int(str_int)

    def loadConfig(self, properties_file=None):
        """
        Load the configuration from the local.properties file or the environment variables.
        """

        # Stop if we already loaded the configuration
        if WebhooksAppTest.config_loaded:
            return

        # Load the port from the environment if possible. This might be get overridden by the
        # local.properties file.
        WebhooksAppTest.port = int(os.environ.get("DEFAULT_TEST_SERVER_PORT",
                                                  WebhooksAppTest.DEFAULT_TEST_SERVER_PORT))

        file_pointer = None

        if properties_file is None:
            properties_file = os.path.join("..", "local.properties")

            try:
                file_pointer = open(properties_file)
            except IOError:
                pass

        if file_pointer is not None:
            regex = re.compile("(?P<key>[^=]+)[=](?P<value>.*)")

            settings = {}

            for line in file_pointer.readlines():
                re_match = regex.search(line)

                if re_match is not None:
                    match_dict = re_match.groupdict()
                    settings[match_dict["key"]] = match_dict["value"]

            # Load the parameters from the local.properties file
            WebhooksAppTest.port = settings.get("value.test.server_port", WebhooksAppTest.port)

    @classmethod
    def start_server(cls):
        """
        Create an instance of the webhooks web-server running SSL.

        The certificate and key were made with the following commands:

            openssl genrsa -des3 -out server.key 1024
            openssl req -new -key server.key -out server.csr
            cp server.key server.key.org
            openssl rsa -in server.key.org -out server.key
            openssl x509 -req -days 365 -in server.csr -signkey server.key -out server.crt
        """

        path_re = cls.path + '/*'

        if cls.protocol == 'https':
            cert_file = os.path.abspath('certs/server.crt')
            key_file = os.path.abspath('certs/server.key')
        else:
            cert_file = None
            key_file = None

        logger = logging.getLogger('test_webhooks')

        def output_results(results):
            """
            This function will get the results from the web-server and verify them.
            """
            for result in results:
                cls.results.append(result)

        cls.results = []
        cls.httpd = WebServer(output_results, cls.port, path_re, cert_file, key_file, logger=logger)
        cls.httpd.start_serving()

    @classmethod
    def setUp(cls):
        """
        Set up the class by clearing the results for the next test.
        """

        # Clear the results so that the tests don't interact with each other
        if cls.results is not None:
            cls.results[:] = []

    @classmethod
    def start_server_thread(cls):
        """
        Start the server thread.
        """

        # Stop the existing server if necessary
        if cls.httpd is not None:
            cls.httpd.stop_serving()
            cls.httpd = None

        # Start the new one
        cls.thread = threading.Thread(target=cls.start_server)
        cls.thread.setDaemon(True)
        cls.thread.start()

        attempts = 0

        sys.stdout.write("Waiting for web-server to start ...")
        sys.stdout.flush()

        while cls.httpd is None and attempts < 75:
            time.sleep(4)
            attempts = attempts + 1
            sys.stdout.write(".")
            sys.stdout.flush()

    @classmethod
    def tearDownClass(cls):
        """
        Shut down the server gracefully.
        """

        if cls.httpd is not None:
            cls.httpd.stop_serving()

class TestWebhooksServer(WebhooksAppTest, unittest.TestCase):
    """
    This tests the input ability to accept data. By default, it will serve a non-SSL connection.
    """
    protocol = 'http'

    def test_run_webserver_with_get(self):
        """
        Try to run the webhooks input and ensure that it loads correctly using a GET
        request.
        """

        url = self.protocol + '://127.0.0.1:' + str(self.port) + self.path \
        + '/TEST?test_run_webserver_with_get=SOMETESTVALUE'
        response = requests.get(url, verify=False, timeout=5)
        response_parsed = json.loads(response.text)

        self.assertEquals(response_parsed['success'], True)
        self.assertEquals(response.status_code, 200)

        self.assertEquals(self.results[0]['test_run_webserver_with_get'][0], 'SOMETESTVALUE')

    def test_run_webserver_with_post(self):
        """
        Try to run the webhooks input and ensure that it loads correctly using a POST
        request.
        """

        url = self.protocol + '://127.0.0.1:' + str(self.port) + self.path + '/TEST'
        data = {
            'test_run_webserver_with_post':'SOMETESTVALUE'
        }

        response = requests.post(url, verify=False, data=data, timeout=5)
        response_parsed = json.loads(response.text)

        self.assertEquals(response_parsed['success'], True)
        self.assertEquals(response.status_code, 200)
        self.assertEquals(self.results[0]['test_run_webserver_with_post'][0], 'SOMETESTVALUE')

    @classmethod
    def setUpClass(cls):
        cls.start_server_thread()

class TestWebhooksServerSSL(TestWebhooksServer):
    """
    This tests the input ability to work with SSL.
    """
    protocol = 'https'

if __name__ == "__main__":
    test_dir = '../tmp/test_reports'
    shutil.rmtree(test_dir, ignore_errors=True)
    unittest.main(testRunner=HtmlTestRunner.HTMLTestRunner(output='../' + test_dir))
