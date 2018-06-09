# sql_scan

My first sql scanner.



Descriptions:
1. Passive scanner, use mitmproxy as proxy.
2. Define various sql rule, support add rules into text file by hand, and convert those rules to xml formet.
3. Support error_based injection, boolean_base injection and time_based injection.
4. Support http and https mode.
5. MultiThread scan target url.
6. Save records into MySQL database.

usage:
1. Configure mitmproxy certificate into your browser.
2. python wyproxy.py -p 8085 -m http

More features will be added:
1. Add more request rules filter.
2. Add more sql rules.
3. Improve code styles and inject rules.

Reference:
1. https://github.com/ring04h/wyproxy/blob/master/wyproxy.py
2. https://github.com/mitmproxy/mitmproxy
