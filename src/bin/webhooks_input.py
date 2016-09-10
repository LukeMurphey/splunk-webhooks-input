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
import splunk

class LogRequestsInSplunkHandler(BaseHTTPRequestHandler):
    
    def handle_request(self):
        
        result = {
                  'path' : self.path,
                  'command' : self.command,
                  'client_address' : self.client_address[0],
                  'client_port' : self.client_address[1]
                 }
        
        self.server.output_results([result])
        self.send_response(200)
        
    def do_GET(self):
        self.handle_request()
        
    def do_POST(self):
        self.handle_request()
        
class WebServer:
    def __init__(self, output_results, port):
        server = HTTPServer(('', port), LogRequestsInSplunkHandler)
        server.output_results = output_results
        server.serve_forever()
    
class WebhooksInput(ModularInput):
    """
    The webhooks input modular input runs a web-server and pipes requests to the HTTP event collector.
    """
    
    def __init__(self, timeout=30, **kwargs):

        scheme_args = {'title': "Webhooks Input",
                       'description': "Retrieve information from webhooks input",
                       'use_external_validation': "true",
                       'streaming_mode': "xml",
                       'use_single_instance': "false"}
        
        args = [
                IntegerField("port", "Port", 'The port to run the web-server on', none_allowed=False, empty_allowed=False),
                #DurationField("interval", "Interval", "The interval defining how often to make sure the server is running", empty_allowed=False)
                ]
        
        ModularInput.__init__( self, scheme_args, args )
        
        if timeout > 0:
            self.timeout = timeout
        else:
            self.timeout = 30
            
        self.http_daemons = []

    def run(self, stanza, cleaned_params, input_config):
        
        # Make the parameters
        interval   = cleaned_params.get("interval", 3600)
        port       = cleaned_params.get("port", 8080)
        sourcetype = cleaned_params.get("sourcetype", "webhooks_input")
        host       = cleaned_params.get("host", None)
        index      = cleaned_params.get("index", "default")
        source     = stanza

        def output_results(results):
            for result in results:
                self.output_event(result, stanza, index=index, source=source, sourcetype=sourcetype, host=host, unbroken=True, close=True)

        # Start the web-server
        self.logger.info("Starting server on port=%r", port)  
        httpd = WebServer(output_results, port)
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