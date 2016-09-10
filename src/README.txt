================================================
Overview
================================================

This app provides a mechanism for indexing data from webhooks.



================================================
Configuring Splunk
================================================

This app exposes a new input type that can be configured in the Splunk Manager. To configure it, create a new input in the Manager under Data inputs > Webhooks.



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

A: Yes, just assign users the "edit_modinput_webhooks_input" capability. You will likely want to give them the "list_inputs" capability too.



================================================
Change History
================================================

+---------+------------------------------------------------------------------------------------------------------------------+
| Version |  Changes                                                                                                         |
+---------+------------------------------------------------------------------------------------------------------------------+
| 0.5     | Initial release                                                                                                  |
+---------+------------------------------------------------------------------------------------------------------------------+
