# coding=utf-8
import unittest
import sys
import os
import json
import logging
import threading
import requests

sys.path.append(os.path.join("..", "src", "bin"))

from webhook import WebServer

class TestSSL(unittest.TestCase):
    httpd = None
    thread = None
    port = None
    path = '/test_run_webserver_with_ssl'
    results = None

    def startServerThread(self):
        """
        Create an instance of the webhooks web-server running SSL.

        The certificate and key were made with the following commands:

            openssl genrsa -des3 -out server.key 1024
            openssl req -new -key server.key -out server.csr
            cp server.key server.key.org
            openssl rsa -in server.key.org -out server.key
            openssl x509 -req -days 365 -in server.csr -signkey server.key -out server.crt
        """

        path_re = self.path + '/*'
        cert_file = os.path.abspath('certs/server.crt')
        key_file = os.path.abspath('certs/server.key')
        logger = logging.getLogger('test_webhooks')
        
        def output_results(results):
            """
            This function will get the results from the web-server and verify them.
            """
            for result in results:
                self.results.append(result)
                print result
                pass
        print "Starting..."
        self.httpd = WebServer(output_results, self.port, path_re, cert_file, key_file, logger=logger)
        #self.httpd = WebServer(output_results, self.port, path_re, logger=logger)
        print "Done"

    def setUp(self):
        self.port = 18080
        self.results = []
        #self.startServerThread()
        thread = threading.Thread(target=self.startServerThread)
        thread.setDaemon(True)
        thread.start()

    def tearDown(self):
        if self.httpd is not None and hasattr(self.httpd, 'socket'):
            self.httpd.socket.close()

        if self.httpd is not None:
            self.httpd.shutdown()

    def test_run_webserver_with_ssl_get(self):
        """
        Try to run the webhooks input with SSL to ensure that it loads correctly using a GET
        request.
        """

        url = 'https://127.0.0.1:' + str(self.port) + self.path + '/TEST?test_run_webserver_with_ssl=SOMETESTVALUE'
        response = requests.get(url, verify=False, timeout=5)
        response_parsed = json.loads(response.text)

        self.assertEquals(response_parsed['success'], True)
        self.assertEquals(response.status_code, 200)
        self.assertEquals(self.results[0]['test_run_webserver_with_ssl'][0], 'SOMETESTVALUE')

if __name__ == "__main__":
    unittest.main()
