import os
import hashlib
import json

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

class HashWrapper:

    def __init__(self):
        pass

    def get_total_hash(self, root_path):
        hash_md5 = hashlib.md5()
        for path, dir, files in os.walk(root_path):
            for file in files:
                file_path = "%s/test.txt" % (path)
                with open(file_path, "rb") as fd:
                    for chunk in iter(lambda: fd.read(4096), b""):
                        hash_md5.update(chunk)
            return hash_md5.hexdigest()

class Main :
    def __init__(self):
        self.config = ConfigParser()
        self.config.get_unit_time()
        temp = HashWrapper().get_total_hash(self.config.get_root())

        print()
if __name__ == "__main__":
    Main()