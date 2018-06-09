import unittest
from utils.parser import *
# from src.parse_xml import *
from src.lib.utils.FileUtils import *

sql_rule = "/Users/looperX/python/security/src/data/filter_sql_rule.txt"
explicit_rule = "/Users/looperX/Devlop/python/src/data/explicit_injection.txt"
time_explicit = "/Users/looperX/Devlop/python/src/data/time_injection.txt"

sql_rule_xml = "/Users/looperX/python/security/src/data/filter_sql_rule.xml"
explicit_rule_xml = "/Users/looperX/Devlop/python/src/data/explicit_injection.xml"
time_explicit_xml = "/Users/looperX/Devlop/python/src/data/time_injection.xml"
url = "http://0.0.0.0:5000/r?id/2511"


class TestProxy(unittest.TestCase):
    # def __init__(self):
    #     self.is_need_url = self.get_need_url()
    #     self.content_type = self.get_content_type()
    #     self.extension = self.get_extension()
    #     self.ispass = self.capture_pass()

    def test_convert_file_to_xml(self):
        FileUtils.convert_file_to_xml(sql_rule, sql_rule_xml)
        FileUtils.convert_file_to_xml(explicit_rule, explicit_rule_xml)
        FileUtils.convert_file_to_xml(time_explicit, time_explicit_xml)

    def test_get_need_url(self):
        start_time = time.time()
        FileUtils.parse(explicit_rule_xml)
        FileUtils.parse(time_explicit_xml)
        # for payload in payloads:
        #     print(payload)
        end_time = time.time()
        spend_time = end_time - start_time
        print("read from xml:" + str(spend_time))
