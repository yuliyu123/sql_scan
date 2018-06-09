import os
import time
import pickle
import xml.etree.ElementTree as ET


class FileUtils(object):

    def __init__(self):
        pass

    @staticmethod
    def clear_file(filename):
        f = open(filename, "w", encoding="utf-8")
        f.truncate()
        f.close()

    @staticmethod
    def write_file(filename, content):
        # f = open(filename, "a+", encoding="utf-8")
        f = open(filename, "a+")
        f.write(content + "\n")

    @staticmethod
    def read_file(filename):
        return open(filename, "r", encoding="utf-8")

    @staticmethod
    def close(filename):
        f = open(filename, "w", encoding="utf-8")
        f.close()

    @staticmethod
    def delete_repeat_line(origin, result):
        f = open(origin, 'r', encoding="utf-8")

        filter = set()

        for line in f:
            filter.add(line)
            print(line)

        fin = open(result, "a+", encoding="utf-8")
        for newline in filter:
            fin.write(newline)

    @staticmethod
    def convert_file_to_xml(src_file, xml_file):
        numline = 0
        if os.path.exists(xml_file):
            FileUtils.clear_file(xml_file)
        f = FileUtils.read_file(src_file)
        start_root = '<root>'
        FileUtils.write_file(xml_file, start_root)
        for line in f:
            newline = "\t<element>\n\t\t" + '<id>' + str(
                numline) + '</id>\n\t\t' + '<payload>' + line.strip() + '</payload>\n\t' + '</element>'
            FileUtils.write_file(xml_file, newline)
            numline += 1
        # FileUtils.close("payloads.xml")
        end_root = '</root>'
        FileUtils.write_file(xml_file, end_root)

    @staticmethod
    def parse(xml_file):
        payload_list = []
        tree = ET.parse(xml_file)
        root = tree.getroot()
        payloads = root.findall("element")
        for child in payloads:
            payload = child.find('payload').text
            payload_list.append(payload)
            # print(l)
        return payload_list
