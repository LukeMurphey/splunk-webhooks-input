================================================
Overview
================================================

This app provides a mechanism for indexing data from webhooks.



================================================
Configuring Splunk
================================================

This app exposes a new input type that can be configured in the Splunk Manager. To configure it, create a new input in the Manager under Data inputs > Webhook.



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
+---------+------------------------------------------------------------------------------------------------------------------+
