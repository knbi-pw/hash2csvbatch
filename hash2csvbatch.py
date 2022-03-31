#!/usr/bin/env python3
import itertools
import sys
import argparse
import time
from datetime import datetime

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
RESULT_FILE_ALT = "result_alt.csv"
maxInt = sys.maxsize

while True:
    # decrease the maxInt value by factor 10
    # as long as the OverflowError occurs.

    try:
        csv.field_size_limit(maxInt)
        break
    except OverflowError:
        maxInt = int(maxInt/10)

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
        self.today_date = int(datetime.utcnow().strftime("%Y%m%d"))

    def set_path_to_cmd_line_arg(self):
        self.path = args.path
        print("Path set to: " + self.path)

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

    def load_md5s_results_from_csv(self):
        with open(RESULT_FILE, "r", newline='', encoding='utf8') as f:
            reader = csv.reader(f)
            self.processed = list(reader)
            self.processed.pop(0)

    def fix_datetime_in_results(self):
        #wyedytowac
        i = 0
        while i < len(self.processed):
            try:
                datetime.strptime(self.processed[i][5], "%Y-%m-%d %H:%M:%S")
                print("Data in correct format, I'm moving forward #" + str(i))
            except ValueError:
                fixed_datetime1 = int(self.processed[i][5])
                self.processed[i][5] = datetime.fromtimestamp(fixed_datetime1)
                fixed_datetime2 = int(self.processed[i][6])
                self.processed[i][6] = datetime.fromtimestamp(fixed_datetime2)
                self.processed_num = self.processed_num + 1
            i = i + 1

    def save_md5s_after_datetime_fix(self):
        time_stamp = str(int(time.time()))
        with open(RESULT_FILE_ALT, 'w', newline='\n', encoding='utf8') as csvfile:
            spamwriter = csv.writer(csvfile, delimiter=",", quotechar='"',
                                    quoting=csv.QUOTE_MINIMAL)
            spamwriter.writerow(['md5', 'file_type_mime', 'signature', 'delivery_method', 'file_information', 'first_seen',
                                 'last_seen', 'yara_rules', 'comments'])
            for e in self.processed:
                spamwriter.writerows([e])
        os.rename(RESULT_FILE, RESULT_FILE + time_stamp)
        time.sleep(2.4)
        os.rename(RESULT_FILE_ALT, RESULT_FILE)

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
        #implement in unforseenable future
        return True

    def search_hash_at_virustotal(self, malware_hash):
        # at least 0.3 second waiting time for request
        time.sleep(0.3)
        headers = {"Accept": "application/json",
                   "x-apikey": "2006e1fdb37824ee7a8386aa483fc96a43ad677aca230f3d927a9d69e653708a"}
        final_url = URL_VIRUSTOTAL + malware_hash
        try:
            response = requests.get(final_url, headers=headers, timeout=5)
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
                    last_submission_date = datetime.fromtimestamp(int(resp_content['data']['attributes']['last_submission_date']))
                    first_submission_date = datetime.fromtimestamp(int(resp_content['data']['attributes']['first_submission_date']))
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

    def search_hash_at_virustotal_third_pass(self, malware_hash):
        # at least 0.3 second waiting time for request
        time.sleep(0.3)
        headers = {"Accept": "application/json",
                   "x-apikey": "BARDDZ_TAJNE_KLUCZYWO/SUPER_SECRET_KEEY"}
        final_url = URL_VIRUSTOTAL + malware_hash
        try:
            response = requests.get(final_url, headers=headers, timeout=

            5)
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
                count = 0
                try:
                    for key in resp_content['data']['attributes']['last_analysis_results']:
                        value = resp_content['data']['attributes']['last_analysis_results'][key]
                        if value['category'] == 'malicious':
                            count == count + 1
                            signature = value['result']
                        if count == 0:
                            return 1
                except KeyError as e:
                    print("No malicious error")
                    return 1
                else:
                    print("200.hash:" + malware_hash)
                    self.save_md5_to_processed_file(self.malware_hash)
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

    def process_md5s_from_unprocessed_list(self, n_pass):
        i = 0
        # commented out due to issue with too low alarm point
        # quota = 0
        while i < len(self.unprocessed_list):
            if n_pass == 2 and self.unprocessed_list[i][1] == "1":
                result_code = self.search_hash_at_virustotal(self.unprocessed_list[i][0])
            elif n_pass == 3 and self.unprocessed_list[i][1] == "2":
                result_code = self.search_hash_at_virustotal_third_pass(self.unprocessed_list[i][0])
            else:
                result_code = 4
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
            elif result_code == 4:
                pass
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

    model.set_path_to_cmd_line_arg()
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

    model.set_path_to_cmd_line_arg()
    model.load_md5s_from_csv()
    model.process_md5s_from_unprocessed_list(2)
    model.display_stats()


def third():
    print('The last and the final search started!')
    model = Model()

    model.set_path_to_cmd_line_arg()
    model.load_md5s_from_csv()
    model.process_md5s_from_unprocessed_list(3)
    model.display_stats()


def datetime_normalization():
    print('Fixing dates to keep them in one, right format')
    model = Model()

    model.set_path_to_cmd_line_arg()
    model.load_md5s_results_from_csv()
    model.fix_datetime_in_results()
    model.save_md5s_after_datetime_fix()
    model.display_stats()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Example parameters')
    parser.add_argument(
        '-f',
        '--mode',
        default='primary',
        help='provide a mode/pass to run'
    )
    parser.add_argument(
        '-p',
        '--path',
        default="C:\\test",
        help='provide an path to look into (default: C:\Test)'
    )
    args = parser.parse_args()
    if args.mode == 'primary':
        main()
    elif args.mode == 'secondary':
        secondary()
    elif args.mode == 'third':
        third()
    elif args.mode == 'datetime_normalization':
        datetime_normalization()
