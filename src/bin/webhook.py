from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
import SocketServer

from splunk.appserver.mrsparkle.lib.util import make_splunkhome_path
from webhooks_input_app.modular_input import ModularInput, Field, IntegerField, DurationField
from splunk.models.base import SplunkAppObjModel

import logging
from logging import handlers
import sys
import time
import os
import re
import json
import urlparse
import errno
from cgi import parse_header, parse_multipart
import splunk

class LogRequestsInSplunkHandler(BaseHTTPRequestHandler):
    
    def handle_request(self, query_args=None):
        
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
        result = {
                  'path' : path_only,
                  'full_path' : self.path,
                  'query' : query,
                  'command' : self.command,
                  'client_address' : self.client_address[0],
                  'client_port' : self.client_address[1]
                 }

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
            for k, v in query_args.items():
                result["parameter_" + k] = v

        # Get the content-body
        content_len = int(self.headers.getheader('content-length', 0))

        if content_len > 0:
            
            post_body = self.rfile.read(content_len)

            try:
                body_json = json.loads(post_body)
            except ValueError:
                # Could not parse output
                body_json = None

            # Get the data and include it
            result.update(body_json)

        # Output the result
        self.server.output_results([result])
        
        # Send a 200 request noting that this worked
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps({"success":True}))
        
    def do_GET(self):
        self.handle_request()
        
    def do_POST(self):
        
        post_args = {}
        
        if 'content-type' in self.headers:
            ctype, pdict = parse_header(self.headers['content-type'])
            
            if ctype == 'multipart/form-data':
                post_args = parse_multipart(self.rfile, pdict)
            elif ctype == 'application/x-www-form-urlencoded':
                length = int(self.headers['content-length'])
                post_args = urlparse.parse_qs(self.rfile.read(length), keep_blank_values=1)
        
        self.handle_request(post_args)
        
class WebServer:
    
    MAX_ATTEMPTS_TO_START_SERVER = 60
    
    def __init__(self, output_results, port, path, logger=None):
        
        try:
            
            # Make an instance of the server
            server = None
            attempts = 0
            
            while server is None and attempts < WebServer.MAX_ATTEMPTS_TO_START_SERVER:
                try:
                    server = HTTPServer(('', port), LogRequestsInSplunkHandler)
                except IOError as e:
                    
                    # Log a message noting that port is taken
                    if logger is not None:
                        logger.info("The web-server could not yet be started, attempt %i of %i", attempts, WebServer.MAX_ATTEMPTS_TO_START_SERVER)
                    
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
            
            # Start the serving
            
            server.serve_forever()
        except IOError as e:
            if server.logger is not None:
                if e.errno == errno.EPIPE:
                    # Broken pipe: happens when the input shuts down or when remote peer disconnects
                    pass
                else:
                    server.logger.warn("IO error when serving the web-server: %s", str(e))
    
class WebhooksInput(ModularInput):
    """
    The webhooks input modular input runs a web-server and pipes data from the requests to Splunk.
    """
    
    def __init__(self, timeout=30, **kwargs):

        scheme_args = {'title': "Webhook",
                       'description': "Retrieve information from a webhook",
                       'use_single_instance': "false"}
        
        args = [
                IntegerField("port", "Port", 'The port to run the web-server on', none_allowed=False, empty_allowed=False),
                Field("path", "Path", 'A wildcard that the path of requests must match (paths generally begin with a "/" and can include a wildcard)', none_allowed=True, empty_allowed=True),
                #DurationField("interval", "Interval", "The interval defining how often to make sure the server is running", empty_allowed=True, none_allowed=True)
                ]
        
        ModularInput.__init__( self, scheme_args, args, logger_name="webhook_modular_input" )
        
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
        
        r = re.escape(wildcard)
        return r.replace('\*', ".*")

    def do_shutdown(self):
        
        to_delete_list = self.http_daemons[:]
        
        self.logger.info("Shutting down the server")
        
        for httpd in to_delete_list:
            httpd.socket.close()
            httpd.shutdown()
            
            del self.http_daemons[httpd]
            

    def run(self, stanza, cleaned_params, input_config):
        
        # Make the parameters
        port       = cleaned_params.get("port", 8080)
        sourcetype = cleaned_params.get("sourcetype", "webhook")
        host       = cleaned_params.get("host", None)
        index      = cleaned_params.get("index", "default")
        path       = cleaned_params.get("path", None)
        source     = stanza

        # Convert the path to a regular expression
        if path is not None and path != "":
            path_re = self.wildcard_to_re(path)
        else:
            path_re = None

        def output_results(results):
            for result in results:
                self.output_event(result, stanza, index=index, source=source, sourcetype=sourcetype, host=host, unbroken=True, close=True)

        # Start the web-server
        self.logger.info("Starting server on port=%r, path=%r", port, path_re)  
        httpd = WebServer(output_results, port, path_re, logger=self.logger)
        self.http_daemons.append(httpd)
            
if __name__ == '__main__':
    webhooks_input = None
    
    try:
        webhooks_input = WebhooksInput()
        webhooks_input.execute()
        sys.exit(0)
    except Exception:
        if webhooks_input is not None and webhooks_input.logger is not None:
            webhooks_input.logger.exception("Unhandled exception was caught, this may be due to a defect in the script") # This logs general exceptions that would have been unhandled otherwise (such as coding errors)
        raise