"""
This module implements a modular input consisting of a web-server that handles incoming Webhooks.
"""

try:
    # Python 2
    from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
    from urlparse import parse_qs

except:
    # Python 3
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from urllib.parse import parse_qs
    unicode = str

import sys
import ssl
import time
import re
import json
import errno
import collections
from threading import Thread
from cgi import parse_header, parse_multipart

import os
path_to_mod_input_lib = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'modular_input.zip')
sys.path.insert(0, path_to_mod_input_lib)
from modular_input import ModularInput, Field, IntegerField, FilePathField

from webhooks_input_app.flatten import flatten

from splunk.clilib.bundle_paths import make_splunkhome_path
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
            self.write_json({"success":False})
            return

        # Make the resulting data
        result = collections.OrderedDict()

        # Parse the query string if need be
        if query_args is None:
            query_args = {}

        if query is not None and query != "":
            query_args_from_path = parse_qs(query, keep_blank_values=True)

            # Merge those obtained from the URL with those obtained from the POST arguments
            if query_args_from_path is not None:
                query_args_from_path.update(query_args)
                query_args = query_args_from_path

        # Add the query arguments to the string
        if query_args is not None:
            for key, value in query_args.items():
                result[key] = value

        # Get the content-body
        content_len = int(self.headers.get('content-length', 0))

        # If content was provided, then parse it
        if content_len > 0 and not content_read_already:

            post_body = self.rfile.read(content_len)
            parsed_body = None

            # Get the type so that we can parse it accordingly
            content_type = self.headers.get('content-type', "application/json")

            # Handle plain text
            if content_type == "text/plain":
                parsed_body = {
                    'data' : post_body
                }

            # Handle JSON
            elif re.search('^application/json([;].*)?', content_type) is not None:
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

        # Convert the output to include strings if needed
        """
        for k, v in result.items():
            key = k
            value = v
            modified = False
        
            if isinstance(v, bytes):
                value = v.decode('utf-8')
                modified = True

            if isinstance(k, bytes):
                key = k.decode('utf-8')
                modified = True

            if modified:
                del result[k]
                result[key] = value
        """

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
        self.write_json({"success":True})

    def write_json(self, json_dict):
        content = json.dumps(json_dict)

        if isinstance(content, unicode):
            content = content.encode('utf-8')
        
        self.wfile.write(content)

    def do_GET(self):
        self.handle_request()

    def do_HEAD(self):
        self.handle_request()

    def read_file(self, length):
        return self.rfile.read(length)

    def do_POST(self):

        post_args = {}
        content_read_already = False

        # Process the results
        if 'content-type' in self.headers:
            ctype, pdict = parse_header(self.headers['content-type'])

            if ctype == 'multipart/form-data':
                post_args = parse_multipart(self.rfile, pdict)
                content_read_already = True
            elif ctype == 'application/x-www-form-urlencoded':
                length = int(self.headers['content-length'])
                post_args = parse_qs(self.rfile.read(length), keep_blank_values=1)
                content_read_already = True

        # Convert 
        for k, v in post_args.items():
            key = k
            modified = False

            # Make the key into a string
            if isinstance(k, bytes):
                key = k.decode('utf-8')
                modified = True

            # Make the values into a list of strings
            converted_values, values_modified = self.convert_list_entries(v)

            # Place the values back if necessary
            if modified or values_modified:
                del post_args[k]
                post_args[key] = converted_values

        self.handle_request(post_args, content_read_already)

    def convert_list_entries(self, args_list):
        updated_list = []
        modified = False

        for entry in args_list:
            if sys.version_info.major >= 3 and isinstance(entry, bytes):
                updated_list.append(entry.decode('utf-8'))
                modified = True
            else:
                updated_list.append(entry)

        return updated_list, modified


class WebServer:
    """
    This class implements an instance of a web-server that listens for incoming webhooks.
    """

    MAX_ATTEMPTS_TO_START_SERVER = 5

    def __init__(self, output_results, port, path, cert_file=None, key_file=None, logger=None):

        # Make an instance of the server
        server = None
        attempts = 0

        while server is None and attempts < WebServer.MAX_ATTEMPTS_TO_START_SERVER:
            try:
                server = HTTPServer(('', port), LogRequestsInSplunkHandler)
            except IOError as exception:

                # Log a message noting that port is taken
                if logger is not None:
                    logger.info('The web-server could not yet be started, attempt %i of %i, reason="%s", pid="%r"',
                                attempts, WebServer.MAX_ATTEMPTS_TO_START_SERVER, str(exception), os.getpid())


                    time.sleep(3)

                server = None
                attempts = attempts + 1

        # Stop if the server could not be started
        if server is None:

            # Log that it couldn't be started
            if logger is not None:
                logger.info('The web-server could not be started, pid="%r"', os.getpid())

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
        except IOError as exception:
            if self.server.logger is not None:
                if exception.errno == errno.EPIPE:
                    # Broken pipe: happens when the input shuts down or when remote peer disconnects
                    pass
                else:
                    self.server.logger.warn("IO error when serving the web-server: %s", str(exception))

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
                       'use_single_instance': True}

        args = [
            IntegerField('port', 'Port', 'The port to run the web-server on', none_allowed=False, empty_allowed=False),
            Field('path', 'Path', 'A wildcard that the path of requests must match (paths generally begin with a "/" and can include a wildcard)', none_allowed=True, empty_allowed=True),
            FilePathField('key_file', 'SSL Certificate Key File', 'The path to the SSL certificate key file (if the certificate requires a key); typically uses .KEY file extension', none_allowed=True, empty_allowed=True, validate_file_existence=True),
            FilePathField('cert_file', 'SSL Certificate File', 'The path to the SSL certificate file (if you want to use encryption); typically uses .DER, .PEM, .CRT, .CER file extensions', none_allowed=True, empty_allowed=True, validate_file_existence=True)
        ]

        ModularInput.__init__(self, scheme_args, args, logger_name="webhook_modular_input", sleep_interval=60)

        if timeout > 0:
            self.timeout = timeout
        else:
            self.timeout = 30

        self.http_daemons = {}

        # This maps the various daemons to the paths & stanzas that are handled
        self.input_map = {}

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

        for stanza, httpd in self.http_daemons.items():
            httpd.stop_serving()
            del self.http_daemons[stanza]

            self.logger.info("Stopping server, stanza=%s, pid=%r", stanza, os.getpid())

    def add_to_input_map(self, port, stanza, path, output_results_fx):
        # Create the entry for this input
        new_handler_entry = {
                stanza: stanza,
                path: path,
                output_results_fx: output_results_fx
            }
        
        # Add the new port entry if necessary
        if port not in self.input_map:
            self.input_map[port] = [new_handler_entry]
            return False

        # Otherwise, add the entry to the existing port
        else:
            existing_entry = self.input_map[port]
            existing_entry.append(new_handler_entry)
            return True

    def handle_webhook_call(self, port):
        pass # TODO

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

        # Log the number of servers that are running
        if self.use_single_instance:
            if hasattr(os, 'getppid'):
                self.logger.info('Number of servers=%r, pid=%s, ppid=%r', len(self.http_daemons), os.getpid(), os.getppid())
            else:
                self.logger.info('Number of servers=%r, pid=%s', len(self.http_daemons), os.getpid())

        # See if the daemon is already started and start it if necessary
        if stanza not in self.http_daemons:

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
            self.logger.info("Starting server on port=%r, path=%r, cert_file=%r, key_file=%r, stanza=%s, pid=%r", port, path_re, cert_file, key_file, source, os.getpid())
            httpd = WebServer(output_results, port, path_re, cert_file, key_file, logger=self.logger)

            if hasattr(httpd, 'server') and httpd.server is not None:
                self.http_daemons[stanza] = httpd

                # Use threads if this is using single instance mode
                if self.use_single_instance:
                    thread = Thread(target=httpd.start_serving)
                    thread.start()

                # Otherwise, just run the server and block on it until it is done
                else:
                    httpd.start_serving()

                self.logger.info("Successfully started server on port=%r, path=%r, cert_file=%r, key_file=%r, stanza=%s, pid=%r", port, path_re, cert_file, key_file, source, os.getpid())

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
