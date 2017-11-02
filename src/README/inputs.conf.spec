[webhook://default]
* Configure an input for retrieving information from a webhook request

port = <value>
* The port to run the input on

path = <value>
* A wildcard that must match the path of the webhooks request
* Example: /my_webhook/*

cert_file = <value>
* A path to an SSL certificate file. Including this will cause the app to use SSL/TLS.
* The file typically uses the file extension of either .DER, .PEM, .CRT, or .CER
* The path will be interpreted relative to the SPLUNK_HOME path if it is relative
* Example: etc/apps/webhooks_input/data/server.crt

key_file = <value>
* A wildcard that must match the path of the webhooks request
* The file typically uses the file extension of .KEY
* The path will be interpreted relative to the SPLUNK_HOME path if it is relative
* Example: etc/apps/webhooks_input/data/server.key