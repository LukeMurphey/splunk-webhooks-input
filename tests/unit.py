# coding=utf-8
import unittest
import sys
import os
import re
import json
import logging
import threading
import requests

sys.path.append(os.path.join("..", "src", "bin"))

from webhook import WebServer

class WebhooksAppTest(unittest.TestCase):
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
    path = '/test_run_webserver_with_ssl'
    results = None

    def toInt(self, str_int):
        if str_int is None:
            return None
        else:
            return int(str_int)

    def loadConfig(self, properties_file=None):

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
    def startServerThread(cls):
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
        cert_file = os.path.abspath('certs/server.crt')
        key_file = os.path.abspath('certs/server.key')
        logger = logging.getLogger('test_webhooks')

        def output_results(results):
            """
            This function will get the results from the web-server and verify them.
            """
            for result in results:
                cls.results.append(result)

        cls.results = []
        cls.httpd = WebServer(output_results, cls.port, path_re, cert_file, key_file, logger=logger)

    @classmethod
    def setUp(cls):
        if cls.results is not None:
            cls.results[:] = []

    @classmethod
    def setUpClass(cls):

        if cls.thread is None:
            cls.thread = threading.Thread(target=cls.startServerThread)
            cls.thread.setDaemon(True)
            cls.thread.start()

class TestSSL(WebhooksAppTest):
    """
    this tests the input ability to work with SSL.
    """

    def test_run_webserver_with_ssl_get(self):
        """
        Try to run the webhooks input with SSL to ensure that it loads correctly using a GET
        request.
        """

        url = 'https://127.0.0.1:' + str(self.port) + self.path \
        + '/TEST?test_run_webserver_with_ssl_get=SOMETESTVALUE'
        response = requests.get(url, verify=False, timeout=5)
        response_parsed = json.loads(response.text)

        self.assertEquals(response_parsed['success'], True)
        self.assertEquals(response.status_code, 200)

        self.assertEquals(self.results[0]['test_run_webserver_with_ssl_get'][0], 'SOMETESTVALUE')

    def test_run_webserver_with_ssl_post(self):
        """
        Try to run the webhooks input with SSL to ensure that it loads correctly using a POST
        request.
        """

        url = 'https://127.0.0.1:' + str(self.port) + self.path + '/TEST'
        data = {
            'test_run_webserver_with_ssl_post':'SOMETESTVALUE'
        }

        response = requests.post(url, verify=False, data=data, timeout=5)
        response_parsed = json.loads(response.text)

        self.assertEquals(response_parsed['success'], True)
        self.assertEquals(response.status_code, 200)
        self.assertEquals(self.results[0]['test_run_webserver_with_ssl_post'][0], 'SOMETESTVALUE')

if __name__ == "__main__":
    unittest.main()
