from apis import *
from functools import wraps
from io import StringIO
import requests
import hashlib
import pandas
import pymongo
import datetime
import simplejson
import configparser
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

'''
The Exporter class stores the state and history of exports

'''


class Exporter:
    def __init__(self, exporter_config):
        self.indexes = []
        self.index_history = {}
        self.polling_interval = int(exporter_config.get("polling_interval"))
        self.cisa_feed = requests.get(
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json").json()


    def get_indexes(self):
        return self.indexes

    def get_index_history(self, index):
        try:
            return self.index_history[index]
        except KeyError:
            return None

    def add_index(self, index, history):
        self.indexes.append(index)
        self.update_history(index, history)

    def update_history(self, index, history):
        self.index_history[index] = history

    # accepts dictionary, converts to string, returns MD5 hash as integer
    def md5_hash(self, data):
        return int(hashlib.md5("{}".format(data).encode('utf-8')).hexdigest(), 16)

    # time in seconds since unix epoch
    def create_timestamp(self):
        return int(datetime.datetime.now().timestamp())

    # converts csv download (in bytes) to dictionary
    def download_to_dict(self, download):
        StringIO_data = StringIO(str(download.content, 'utf-8'))
        data_frame = pandas.read_csv(StringIO_data)
        return data_frame.to_dict(orient="records")

    def construct_url(self, protocol, ip, port):
        return f"{protocol}://{ip}:{port}"

    def exploited_cves(self):
        return [item["cveID"] for item in self.cisa_feed["vulnerabilities"]]

    def in_cisa_feed(self, cve):
        return cve in self.exploited_cves()

    def benchmark(func):
        """
        A decorator that prints the time a function takes
        to execute.
        """
        import time
        @wraps(func)
        def wrapper(*args, **kwargs):
            t1 = time.time()
            created, existed = func(*args, **kwargs)
            t2 = time.time() - t1
            return created, existed, t2

        return wrapper


'''
ELKImporter inherits from Exporter Class
'''


class ELKImporter(Exporter):
    def __init__(self, elk_config, **kwargs):
        super().__init__(kwargs["exporter_config"])  # call the super-class' constructor
        self.elk_url = self.construct_url(elk_config.get("protocol"), elk_config.get("ip"), elk_config.get("port"))
        self.elk_auth = elk_config.get("auth")
        self.elk = ELK(self.elk_url, self.elk_auth)

    def mappings(self):
        return """ {
                      "mappings": {
                        "properties": {
                          "date": {
                            "type":   "date",
                            "format": "epoch_second"
                          }
                        }
                      }
                    }"""

    @Exporter.benchmark
    def export_scan(self, nessus, scan):
        create_counter = 0
        exists_counter = 0
        data = self.download_to_dict(nessus.full_download(scan["id"]))
        scan_name = scan["name"].replace(" ", "_").lower()
        index = f"nessus_{scan_name}"
        resp = self.elk.set_mappings(index, self.mappings())
        for row in data:
            _id = self.md5_hash(row)
            if self.elk.document_exists(index, _id):
                exists_counter += 1
            else:
                create_counter += 1
                row["date"] = self.create_timestamp()
                row["in_cisa_feed"] = self.in_cisa_feed(row["CVE"])
                json = simplejson.dumps(row, ignore_nan=True)
                resp = self.elk.create_document(index, _id, json)

        return create_counter, exists_counter


'''
MongoImporter inherits from Exporter Class
'''


class MongoImporter(Exporter):
    def __init__(self, mongo_config, **kwargs):
        super().__init__(kwargs["exporter_config"])  # call the super-class' constructor
        self.mongo_url = mongo_config.get("url")
        self.mongo_client = pymongo.MongoClient(self.mongo_url)
        self.db = self.mongo_client["Nessus"]

    def md5_digest(self, data):
        return hashlib.md5(f"{data}".encode('utf-8')).hexdigest()

    def document_exists(self, collection, _id):
        insert = {}
        insert["md5"] = _id
        if self.db.get_collection(collection).find_one(insert) is None:
            return False
        else:
            return True

    def insert_document(self, collection, d):
        return self.db.get_collection(collection).insert_one(d)

    def insert_bulk(self, collection, data):
        return self.db.get_collection(collection).insert_many(data)

    @Exporter.benchmark
    def export_scan(self, nessus, scan):
        create_counter = 0
        exists_counter = 0
        data = self.download_to_dict(nessus.full_download(scan["id"]))
        scan_name = scan["name"].replace(" ", "_").lower()
        collection = f"nessus_{scan_name}"
        for row in data:
            _id = self.md5_digest(row)
            if self.document_exists(collection, _id):
                exists_counter += 1
            else:
                create_counter += 1
                row["md5"] = _id
                row["date"] = self.create_timestamp()
                row["in_cisa_feed"] = self.in_cisa_feed(row["CVE"])
                resp = self.insert_document(collection, row)

            #resp = self.insert_bulk(collection, data)

        return create_counter, exists_counter
