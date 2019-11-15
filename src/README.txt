================================================
Overview
================================================

This app provides a mechanism for indexing data from webhooks.



================================================
Configuring Splunk
================================================

Install this app into Splunk by doing the following:

  1. Log in to Splunk Web and navigate to "Apps » Manage Apps" via the app dropdown at the top left of Splunk's user interface
  2. Click the "install app from file" button
  3. Upload the file by clicking "Choose file" and selecting the app
  4. Click upload
  5. Restart Splunk if a dialog asks you to

Once the app is installed, you can use the app by configuring a new input:
  1. Navigate to "Settings » Data Inputs" at the menu at the top of Splunk's user interface.
  2. Click "Webhook"
  3. Click "New" to make a new instance of an input



================================================
Getting Support
================================================

Go to the following website if you need support:

     http://splunk-base.splunk.com/apps/3308/answers/

You can access the source-code and get technical details about the app at:

     https://github.com/LukeMurphey/splunk-webhooks-input



================================================
FAQ
================================================

Q: Can I allow non-admin users to make and edit inputs?

A: Yes, just assign users the "edit_modinput_webhook" capability. You will likely want to give them the "list_inputs" capability too.



================================================
Change History
================================================

+---------+------------------------------------------------------------------------------------------------------------------+
| Version |  Changes                                                                                                         |
+---------+------------------------------------------------------------------------------------------------------------------+
| 0.5     | Initial release                                                                                                  |
|---------|------------------------------------------------------------------------------------------------------------------|
| 0.6     | Various minor changes                                                                                            |
|---------|------------------------------------------------------------------------------------------------------------------|
| 0.7     | Changed input to simply "webhook" from "webhooks_input"                                                          |
|         | Input now attempts to get an open port for 2 minutes if the port is already taken                                |
|---------|------------------------------------------------------------------------------------------------------------------|
| 1.0     | Added support for parsing incoming data from the content-body                                                    |
|         | Fixed error indicating that a socket didn't exist that sometimes happened when shutting down                     |
|         | Fields based on the GET and POST parameters are no longer prepended with "parameter_"                            |
|---------|------------------------------------------------------------------------------------------------------------------|
| 1.1     | Added support for HEAD requests which allows ths input to work with Trello                                       |
|---------|------------------------------------------------------------------------------------------------------------------|
| 1.2     | Added support for using SSL/TLS                                                                                  |
|         | Fixed issue where POST requests would sometimes freeze                                                           |
|---------|------------------------------------------------------------------------------------------------------------------|
| 1.2.1   | Added better logging for why a port could not be opened                                                          |
|         | Fixed issue where sometimes the port was not opened when restarting                                              |
|         | Changed input to single-instance mode; only one instance of code will now manage all of the inputs               |
|---------|------------------------------------------------------------------------------------------------------------------|
| 1.2.2   | Fixed issue where the webhook didn't recognize incoming JSON when the HTTP header included the encoding          |
|---------|------------------------------------------------------------------------------------------------------------------|
| 1.2.3   | Added support for Python 2 & 3                                                                                   |
+---------+------------------------------------------------------------------------------------------------------------------+
