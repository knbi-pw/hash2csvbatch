#!/usr/bin/env python3
import itertools
import sys
import time
import datetime

import requests
import os
import re
import csv

URL = 'https://mb-api.abuse.ch/api/v1/'
URL_VIRUSTOTAL = 'https://www.virustotal.com/api/v3/files/'
QUOTA_DAILY_VIRUSTOTAL = 20000
# per minute
REQUEST_RATE_VIRUSTOTAL = 1000
LOG_FILE = "processed.log"
PROCESSED_HASH_FILE = "processed_md5s.csv"
NOT_PROCESSED_YET_FILE = "processed_not_yet.csv"
NOT_PROCESSED_YET_ALT_FILE = "processed_not_yet_alt.csv"
RESULT_FILE = "result.csv"
PATH = "C:\\test"


class Model(object):
    def __init__(self):
        self.path = None
        self.malware_hash = None
        self.processed = []
        self.to_process_files = []
        self.list_md5_processed = []
        self.unprocessed_list = None
        self.processed_num = 0
        self.unprocessed_num = 0
        self.today_date = int(datetime.datetime.utcnow().strftime("%Y%m%d"))

    def set_path_to_cmd_line_arg(self, path):
        self.path = path
        print(path)

    def create_file_if_not_exist(self, fname):
        if not os.path.isfile(fname):
            if fname == RESULT_FILE:
                open(fname, "x")
                with open(fname, "w", newline='') as result_file:
                    spamwriter = csv.writer(result_file, delimiter=",", quotechar='"', quoting=csv.QUOTE_MINIMAL)
                    spamwriter.writerow(
                        ['md5', 'file_type_mime', 'signature', 'delivery_method', 'file_information', 'first_seen',
                         'last_seen', 'yara_rules', 'comments'])
            else:
                open(fname, "x")

    def already_processed_gen_list(self):
        with open(LOG_FILE, "r", newline='') as already_processed:
            reader = csv.reader(already_processed)
            self.processed = list(reader)
            self.processed = list(itertools.chain(*self.processed))

    def to_process_gen_list(self):
        for root, d_names, f_names in os.walk(self.path):
            for f in f_names:
                file_full_path = os.path.join(root, f)
                if f == "summary.txt":
                    if file_full_path not in self.processed:
                        self.to_process_files.append(file_full_path)

    def md5_processed_gen_list(self):
        with open(PROCESSED_HASH_FILE, "r", newline='') as file:
            csv_reader = csv.reader(file)
            for row in csv_reader:
                self.list_md5_processed.append(row)
        self.list_md5_processed = list(itertools.chain(*self.list_md5_processed))

    def load_md5s_from_csv(self):
        with open(NOT_PROCESSED_YET_FILE, "r", newline='') as f:
            reader = csv.reader(f)
            self.unprocessed_list = list(reader)
            self.unprocessed_list.pop(0)

    def save_md5_to_processed_file(self, final_hash):
        with open(PROCESSED_HASH_FILE, 'a', newline='') as csvfile:
            spamwriter = csv.writer(csvfile, delimiter=",", quotechar='"',
                                    quoting=csv.QUOTE_MINIMAL)
            spamwriter.writerow([final_hash])

    def save_md5s_to_unprocessed_file(self):
        time_stamp = str(int(time.time()))
        with open(NOT_PROCESSED_YET_ALT_FILE, 'w', newline="\n") as csvfile:
            spamwriter = csv.writer(csvfile, delimiter=",", quotechar='"',
                                    quoting=csv.QUOTE_MINIMAL)
            spamwriter.writerow(['hash', 'tries'])
            for e in self.unprocessed_list:
                spamwriter.writerows([e])
        os.rename(NOT_PROCESSED_YET_FILE, NOT_PROCESSED_YET_FILE + time_stamp)
        time.sleep(2.4)
        os.rename(NOT_PROCESSED_YET_ALT_FILE, NOT_PROCESSED_YET_FILE)

    def find_md5s_at_virustotal(self):
        return True

    def search_hash_at_virustotal(self, malware_hash):
        # at least 0.3 second waiting time for request
        time.sleep(0.3)
        headers = {"Accept": "application/json",
                   "x-apikey": "SUPER_TAJNE_HASLO/TOP_SECRET_KEEY"}
        final_url = URL_VIRUSTOTAL + malware_hash
        try:
            response = requests.get(final_url, headers=headers, timeout=15)
            if response.status_code == 429:
                print("END OF QUOTA (VIRUSTOTAL)")
                return 3
            response.raise_for_status()
        except requests.exceptions.HTTPError as errh:
            print("Http Error:", errh)
            self.unprocessed_num = self.unprocessed_num + 1
            return 1
        except requests.exceptions.ConnectionError as errc:
            print("Error Connecting:", errc)
            self.unprocessed_num = self.unprocessed_num + 1
            return 1
        except requests.exceptions.Timeout as errt:
            print("Timeout Error:", errt)
            self.unprocessed_num = self.unprocessed_num + 1
            return 1
        except requests.exceptions.RequestException as err:
            print("OOps: Something Else", err)
            self.search_hash_at_virustotal(malware_hash)
        else:
            if response.status_code == 200:
                resp_content = response.json()
                try:
                    if resp_content['data']['attributes']['last_analysis_results']['Avast']['category'] != 'malicious':
                        return 1
                except KeyError as e:
                    print("No avast error")
                    return 1
                else:
                    print("200.hash:" + malware_hash)
                    self.save_md5_to_processed_file(self.malware_hash)
                    signature = resp_content['data']['attributes']['last_analysis_results']['Avast']['result']
                    last_submission_date = resp_content['data']['attributes']['last_submission_date']
                    first_submission_date = resp_content['data']['attributes']['first_submission_date']
                    with open(RESULT_FILE, 'a', encoding="utf-8", newline='') as csvfile:
                        spamwriter = csv.writer(csvfile, delimiter=",", quotechar='"',
                                                quoting=csv.QUOTE_MINIMAL)
                        spamwriter.writerow(
                            [malware_hash, None,
                             signature,
                             None,
                             None,
                             first_submission_date,
                             last_submission_date,
                             None,
                             None
                             ])
                self.processed_num = self.processed_num + 1
                return 0

    def process_md5s_from_unprocessed_list(self):
        i = 0
        # commented out due to issue with too low alarm point
        # quota = 0
        while i < len(self.unprocessed_list):
            if self.unprocessed_list[i][1] == "1":
                result_code = self.search_hash_at_virustotal(self.unprocessed_list[i][0])
                if result_code == 0:
                    self.unprocessed_list.pop(i)
                elif result_code == 1:
                    self.unprocessed_list[i][1] = int(self.unprocessed_list[i][1]) + 1
                elif result_code == 2:
                    self.unprocessed_list[i][1] = int(self.unprocessed_list[i][1]) + 1
                    break
                elif result_code == 3:
                    self.unprocessed_list[i][1] = int(self.unprocessed_list[i][1]) + 1
                    break
                else:
                    self.unprocessed_list[i][1] = int(self.unprocessed_list[i][1]) + 1
                    break
            i = i + 1
            # commented out due to issue with too low alarm point
            # quota = quota + 1
            # if quota == QUOTA_DAILY_VIRUSTOTAL:
            #    if int(datetime.datetime.utcnow().strftime("%Y%m%d")) > self.today_date:
            #        quota = 0
            #    else:
            #        print("END OF QUOTA (VIRUSTOTAL)")
            #        break
        self.save_md5s_to_unprocessed_file()

    def save_hash_to_not_yet_found_list(self, malware_hash):
        with open(NOT_PROCESSED_YET_FILE, 'a', newline='') as csvfile:
            spamwriter = csv.writer(csvfile, delimiter=",", quotechar='"',
                                    quoting=csv.QUOTE_MINIMAL)
            spamwriter.writerow([malware_hash, 1])

    def find_md5s_and_generate_csvs(self):
        for item in self.to_process_files:
            self.process_single_summary(item)

    def process_single_summary(self, item):
        with open(item, "r") as file:
            lines = file.readlines()
            self.process_single_line(lines)

    def process_single_line(self, lines):
        for line in lines:
            x = re.search("(?<=MD5:)(\\s*)([a-fA-F0-9]{32}$)", line)
            if x:
                final_md5 = x.group().strip()
                self.final_md5_processing(final_md5)

    def final_md5_processing(self, final_md5):
        if final_md5 not in self.list_md5_processed:
            data = {"query": "get_info", "hash": final_md5}
            response = requests.post(URL, data=data)
            print(response.status_code)
            if response.content is None or response.content == '':
                print('Null or empty response')
            if response.status_code == 200:
                resp_content = response.json()
                if resp_content["query_status"] != "hash_not_found":
                    self.save_md5_to_processed_file(final_md5)
                    with open(RESULT_FILE, 'a', encoding="utf-8", newline='') as csvfile:
                        spamwriter = csv.writer(csvfile, delimiter=",", quotechar='"',
                                                quoting=csv.QUOTE_MINIMAL)
                        spamwriter.writerow(
                            [final_md5, resp_content["data"][0]["file_type_mime"],
                             resp_content["data"][0]["signature"],
                             resp_content["data"][0]["delivery_method"],
                             resp_content["data"][0]["file_information"],
                             resp_content["data"][0]["first_seen"],
                             resp_content["data"][0]["last_seen"],
                             resp_content["data"][0]["yara_rules"],
                             resp_content["data"][0]["comments"]
                             ])
                    self.processed_num = self.processed_num + 1
                else:
                    if not self.search_hash_at_virustotal(final_md5):
                        self.save_hash_to_not_yet_found_list(final_md5)
                        self.unprocessed_num = self.unprocessed_num + 1

    def gen_processed_in_this_session_result(self):
        if self.to_process_files:
            with open(LOG_FILE, "a") as processed_in_this_session:
                wr = csv.writer(processed_in_this_session, delimiter=",", quotechar='"', quoting=csv.QUOTE_MINIMAL)
                wr.writerows([self.to_process_files])

    def display_stats(self):
        print('Processed hashes:', self.processed_num, ' Unprocessed hashes:', self.unprocessed_num)


def main():
    print('Primary search started!')
    model = Model()

    model.set_path_to_cmd_line_arg(sys.argv[-1])
    model.create_file_if_not_exist(LOG_FILE)
    model.create_file_if_not_exist(PROCESSED_HASH_FILE)
    model.create_file_if_not_exist(NOT_PROCESSED_YET_FILE)
    model.create_file_if_not_exist(RESULT_FILE)
    model.already_processed_gen_list()
    model.to_process_gen_list()
    model.md5_processed_gen_list()
    model.find_md5s_and_generate_csvs()
    model.gen_processed_in_this_session_result()
    model.display_stats()


def secondary():
    print('Alternative search started!')
    model = Model()

    model.load_md5s_from_csv()
    model.process_md5s_from_unprocessed_list()
    model.display_stats()


def third():
    pass


if __name__ == '__main__':
    if sys.argv[-2] == '-f':
        if sys.argv[-1] == 'secondary':
            secondary()
        elif sys.argv[-1] == 'third':
            third()
    elif sys.argv[-2] == '-p':
        main()
