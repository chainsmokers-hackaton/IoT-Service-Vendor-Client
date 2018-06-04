import os
import hashlib
import json
import time
import threading
import socket
import pickle
import requests

class LogWrapper:
    logger = None
    def __init__(self, name):
        pass

    def get_logger(self):
        return self.logger

CONFIG_PATH = "./config.json"
logger = LogWrapper("IoTServiceVendorClient").get_logger()

class ConfigParser:
    def __init__(self):
        with open(CONFIG_PATH) as fd:
            self.config = json.load(fd)

    def get_mode(self):
        if "debug" in self.config:
            return self.config["mode"]

    def get_root(self):
        if "root_path" in self.config:
            return self.config["root_path"]

    def get_unit_time(self):
        if "unit_time" in self.config:
            if self.config["unit_time"][-1].lower() == "s":
                return int(self.config["unit_time"][0:-1])
            elif self.config["unit_time"][-1].lower() == "M":
                return int(self.config["unit_time"][0:-1]) * 60
            elif self.config["unit_time"][-1].lower() == "h":
                return int(self.config["unit_time"][0:-1]) * 60 * 60

    def get_host_ip(self):
        if "host_ip" in self.config:
            return self.config["host_ip"]

    def get_host_port(self):
        if "host_port" in self.config:
            return self.config["host_port"]

    def get_server_url(self):
        if "server_url" in self.config:
            return self.config["server_url"]

class HashWrapper:

    def __init__(self):
        pass

    @staticmethod
    def check_elf_file(file_path):
        fd = open(file_path, "rb")
        signature = fd.read(4)
        if signature == b"\x7fELF":
            return True
        else:
            return False

    def get_total_hash(self, root_path):
        hash_md5 = hashlib.md5()
        for path, dir, files in os.walk(root_path):
            for file in files:
                file_path = "%s/%s" % (path, file)
                try:
                    if self.check_elf_file(file_path) == False: continue
                    fd = open(file_path, "rb")
                except Exception as e:
                    continue
                else:
                    for chunk in iter(lambda: fd.read(4096), b""):
                        hash_md5.update(chunk)
        print(hash_md5.hexdigest()) # add log
        return hash_md5.hexdigest()

    def get_each_hash(self, root_path):
        hash_list = list()
        for path, dir, files in os.walk(root_path):
            for file in files:
                file_path = "%s/%s" % (path, file)
                try:
                    if self.check_elf_file(file_path) == False: continue
                    fd = open(file_path, "rb")
                except Exception as e:
                    continue
                else:
                    hash_md5 = hashlib.md5()
                    for chunk in iter(lambda: fd.read(4096), b""):
                        hash_md5.update(chunk)

                    hash_list.append((file_path, hash_md5.hexdigest()))
        return hash_list

class TransactionThread(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.config = ConfigParser()
        self.hash_wrapper = HashWrapper()

    def run(self):
        while True:
            hash_value = self.hash_wrapper.get_total_hash(self.config.get_root())
            print(hash_value)
            # add function to make transaction
            time.sleep(self.config.get_unit_time())

class ResponseToServer(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.config = ConfigParser()
        self.hash_wrapper = HashWrapper()

    def collect_black_hash(self, white_hash_list):
        black_hash_list = list()
        current_hash_list = self.hash_wrapper.get_each_hash(self.config.get_root())

        for current_file in current_hash_list:
            for white_file in white_hash_list:
                if current_file[1] != white_file:
                    if len(black_hash_list) == 0:
                        black_hash_list.append(current_file)

                    for black_bin in black_hash_list:
                        if current_file[1] == black_bin[1]: continue
                        black_hash_list.append(current_file)

        for black_file in black_hash_list:
            with open(black_file[0], "rb") as file:
                file_info = {"file":file}
                result = requests.post(self.config.get_server_url(), files=file_info)

                if result.status_code == 200:
                    print("") # add log to success
                else:
                    print("") # add log to fail



    def run(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind((self.config.get_host_ip(), int(self.config.get_host_port())))
            sock.listen(1)

            while True:
                conn, addr = sock.accept()
                operator = conn.recv(1048576)
                if len(operator) > 0:
                    operator = pickle.loads(operator)
                    
                    if "operator" in operator:
                        operation = operator.pop("operator")

                        if operation == "get_black_bin":
                            self.collect_black_hash(operator["white_hash_list"])




class Main:
    def __init__(self):
        transaction_thread = TransactionThread()
        transaction_thread.start()

        response_to_server_thread = ResponseToServer()
        response_to_server_thread.start()

if __name__ == "__main__":
    Main()