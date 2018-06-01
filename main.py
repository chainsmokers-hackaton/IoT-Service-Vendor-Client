import os
import hashlib
import json
import time
import threading
import socket
import pickle

CONFIG_PATH = "./config.json"

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

class HashWrapper:

    def __init__(self):
        pass

    def get_total_hash(self, root_path):
        hash_md5 = hashlib.md5()
        for path, dir, files in os.walk(root_path):
            for file in files:
                file_path = "%s/%s" % (path, file)
                try:
                    fd = open(file_path, "rb")
                except Exception as e:
                    continue
                else:
                    for chunk in iter(lambda: fd.read(4096), b""):
                        hash_md5.update(chunk)
        print(hash_md5.hexdigest())
        return hash_md5.hexdigest()

    def get_each_hash(self, root_path):
        hash_list = list()
        for path, dir, files in os.walk(root_path):
            for file in files:
                file_path = "%s/%s" % (path, file)
                try:
                    fd = open(file_path, "rb")
                except Exception as e:
                    continue
                else:
                    hash_md5 = hashlib.md5()
                    for chunk in iter(lambda: fd.read(4096), b""):
                        hash_md5.update(chunk)
                    hash_list.append(hash_md5.hexdigest())
        return hash_list

class TransactionThread(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.config = ConfigParser()
        self.hash_wrapper = HashWrapper()

    def run(self):
        hash_value = self.hash_wrapper.get_total_hash(self.config.get_root())
        print(hash_value)
        # add make transaction
        time.sleep(self.config.get_unit_time())

class ResponseToServer(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.config = ConfigParser()

    def run(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind((self.config.get_host_ip(), int(self.config.get_host_port())))
            sock.listen(1)

            while True:
                conn, addr = sock.accept()
                operator = conn.recv(1048576)
                if len(operator) > 0:
                    operator = pickle.loads(operator)
                    print(operator)
                # if operator == ""

class Main:
    def __init__(self):
        # transaction_thread = TransactionThread()
        # transaction_thread.start()

        response_to_server_thread = ResponseToServer()
        response_to_server_thread.start()

        # threading.Timer()
        # temp = HashWrapper().get_total_hash(self.config.get_root())
        # temp = HashWrapper().get_each_hash(self.config.get_root())

if __name__ == "__main__":
    Main()