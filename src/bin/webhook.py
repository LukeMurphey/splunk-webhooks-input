"""
This module implements a modular input consisting of a web-server that handles incoming Webhooks.
"""

from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer

import sys
import ssl
import time
import re
import json
import urlparse
import errno
import collections
from cgi import parse_header, parse_multipart

from webhooks_input_app.modular_input import ModularInput, Field, IntegerField, FilePathField
from webhooks_input_app.flatten import flatten

from splunk.appserver.mrsparkle.lib.util import make_splunkhome_path
from splunk.models.base import SplunkAppObjModel
import splunk

class LogRequestsInSplunkHandler(BaseHTTPRequestHandler):

    def handle_request(self, query_args=None, content_read_already=False):

        # Get the simple path (without arguments)
        if self.path.find("?") < 0:
            path_only = self.path
            query = ""
        else:
            path_only = self.path[0:self.path.find("?")]
            query = self.path[self.path.find("?")+1:]

        # Verify that the request matches the path, return a 404 otherwise
        if self.server.path is not None and not re.match(self.server.path, path_only):
            self.send_response(404)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"success":False}))
            return

        # Make the resulting data
        result = collections.OrderedDict()

        # Parse the query string if need be
        if query_args is None:
            query_args = {}

        if query is not None and query != "":
            query_args_from_path = urlparse.parse_qs(query, keep_blank_values=True)

            # Merge those obtained from the URL with those obtained from the POST arguments
            if query_args_from_path is not None:
                query_args_from_path.update(query_args)
                query_args = query_args_from_path

        # Add the query arguments to the string
        if query_args is not None:
            for key, value in query_args.items():
                result[key] = value

        # Get the content-body
        content_len = int(self.headers.getheader('content-length', 0))

        if content_len > 0 and not content_read_already:

            post_body = self.rfile.read(content_len)
            parsed_body = None

            content_type = self.headers.getheader('content-type', "application/json")

            # Handle plain text
            if content_type == "text/plain":
                parsed_body = {
                    'data' : post_body
                }

            # Handle JSON
            elif content_type == "application/json":
                try:
                    body_json = json.loads(post_body)
                    parsed_body = flatten(body_json)
                except ValueError:
                    # Could not parse output
                    parsed_body = None

                    if self.server.logger is not None:
                        self.server.logger.warn("Content body could not be parsed as JSON")

            # Include the data if we got some
            if parsed_body is not None:
                result.update(parsed_body)

        # Add the data regarding the query
        result['path'] = path_only
        result['full_path'] = self.path
        result['query'] = query
        result['command'] = self.command
        result['client_address'] = self.client_address[0]
        result['client_port'] = self.client_address[1]

        # Output the result
        self.server.output_results([result])

        # Send a 200 request noting that this worked
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps({"success":True}))

    def do_GET(self):
        self.handle_request()

    def do_HEAD(self):
        self.handle_request()

    def do_POST(self):

        post_args = {}
        content_read_already = False

        if 'content-type' in self.headers:
            ctype, pdict = parse_header(self.headers['content-type'])

            if ctype == 'multipart/form-data':
                post_args = parse_multipart(self.rfile, pdict)
                content_read_already = True
            elif ctype == 'application/x-www-form-urlencoded':
                length = int(self.headers['content-length'])
                post_args = urlparse.parse_qs(self.rfile.read(length), keep_blank_values=1)
                content_read_already = True

        self.handle_request(post_args, content_read_already)

class WebServer:
    """
    This class implements an instance of a web-server that listens for incoming webhooks.
    """

    MAX_ATTEMPTS_TO_START_SERVER = 60

    def __init__(self, output_results, port, path, cert_file=None, key_file=None, logger=None):

        # Make an instance of the server
        server = None
        attempts = 0

        while server is None and attempts < WebServer.MAX_ATTEMPTS_TO_START_SERVER:
            try:
                server = HTTPServer(('', port), LogRequestsInSplunkHandler)
            except IOError as e:

                # Log a message noting that port is taken
                if logger is not None:
                    logger.info("The web-server could not yet be started, attempt %i of %i",
                                attempts, WebServer.MAX_ATTEMPTS_TO_START_SERVER)

                server = None
                time.sleep(2)
                attempts = attempts + 1

        # Stop if the server could not be started
        if server is None:

            # Log that it couldn't be started
            if logger is not None:
                logger.info("The web-server could not be started")

            # Stop, we weren't successful
            return

        # Save the parameters
        server.output_results = output_results
        server.path = path
        server.logger = logger

        # Setup a SSL socket if necessary
        if cert_file is not None:
            server.socket = ssl.wrap_socket(
                server.socket, certfile=cert_file, keyfile=key_file, server_side=True)

        # Keep a server instance around
        self.server = server

    def start_serving(self):
        """
        Start the server.
        """

        try:
            self.server.serve_forever()
        except IOError as e:
            if self.server.logger is not None:
                if e.errno == errno.EPIPE:
                    # Broken pipe: happens when the input shuts down or when remote peer disconnects
                    pass
                else:
                    self.server.logger.warn("IO error when serving the web-server: %s", str(e))

    def stop_serving(self):
        """
        Stop the server.
        """

        self.server.shutdown()

        # https://lukemurphey.net/issues/1908
        if hasattr(self.server, 'socket'):
            self.server.socket.close()

class WebhooksInput(ModularInput):
    """
    The webhooks input modular input runs a web-server and pipes data from the requests to Splunk.
    """

    def __init__(self, timeout=30, **kwargs):

        scheme_args = {'title': "Webhook",
                       'description': "Retrieve information from a webhook",
                       'use_single_instance': "false"}

        args = [
            IntegerField('port', 'Port', 'The port to run the web-server on', none_allowed=False, empty_allowed=False),
            Field('path', 'Path', 'A wildcard that the path of requests must match (paths generally begin with a "/" and can include a wildcard)', none_allowed=True, empty_allowed=True),
            FilePathField('key_file', 'SSL Certificate Key File', 'The path to the SSL certificate key file (if the certificate requires a key); typically uses .KEY file extension', none_allowed=True, empty_allowed=True, validate_file_existence=True),
            FilePathField('cert_file', 'SSL Certificate File', 'The path to the SSL certificate file (if you want to use encryption); typically uses .DER, .PEM, .CRT, .CER file extensions', none_allowed=True, empty_allowed=True, validate_file_existence=True)
        ]

        ModularInput.__init__(self, scheme_args, args, logger_name="webhook_modular_input")

        if timeout > 0:
            self.timeout = timeout
        else:
            self.timeout = 30

        self.http_daemons = []

    @classmethod
    def wildcard_to_re(cls, wildcard):
        """
        Convert the given wildcard to a regular expression.

        Arguments:
        wildcard -- A string representing a wild-card (like "/some_path/*")
        """

        regex_escaped = re.escape(wildcard)
        return regex_escaped.replace('\*', ".*")

    def do_shutdown(self):

        to_delete_list = self.http_daemons[:]

        self.logger.info("Shutting down the server")

        for httpd in to_delete_list:
            httpd.stop_serving()

            del self.http_daemons[httpd]

    def run(self, stanza, cleaned_params, input_config):

        # Make the parameters
        port = cleaned_params.get("port", 8080)
        key_file = cleaned_params.get("key_file", None)
        cert_file = cleaned_params.get("cert_file", None)

        sourcetype = cleaned_params.get("sourcetype", "webhook")
        host = cleaned_params.get("host", None)
        index = cleaned_params.get("index", "default")
        path = cleaned_params.get("path", None)
        source = stanza

        # Convert the path to a regular expression
        if path is not None and path != "":
            path_re = self.wildcard_to_re(path)
        else:
            path_re = None

        def output_results(results):
            """
            This function will get the web-server to output the results to Splunk.
            """
            for result in results:
                self.output_event(result, stanza, index=index, source=source, sourcetype=sourcetype, host=host, unbroken=True, close=True)

        # Start the web-server
        self.logger.info("Starting server on port=%r, path=%r, cert_file=%r, key_file=%r", port, path_re, cert_file, key_file)
        httpd = WebServer(output_results, port, path_re, cert_file, key_file, logger=self.logger)
        self.http_daemons.append(httpd)
        httpd.start_serving()

if __name__ == '__main__':
    webhooks_input = None

    try:
        webhooks_input = WebhooksInput()
        webhooks_input.execute()
        sys.exit(0)
    except Exception:
        if webhooks_input is not None and webhooks_input.logger is not None:
             # This logs general exceptions that would have been unhandled otherwise (such as coding errors)
            webhooks_input.logger.exception("Unhandled exception was caught, this may be due to a defect in the script")
        raise
