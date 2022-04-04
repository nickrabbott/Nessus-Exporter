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
    def __init__(self):
        self.indexes = []
        self.index_history = {}
        self.config = configparser.ConfigParser()
        self.config.read("../config/config.ini")
        self.config.sections()
        self.nessus_url = self.construct_url(self.config["NESSUS"]["Protocol"],self.config["NESSUS"]["IP"],self.config["NESSUS"]["Port"])
        self.nessus_access_key = self.config["NESSUS"]["Access_Key"]
        self.nessus_secret_key = self.config["NESSUS"]["Secret_Key"]
        self.polling_interval = int(self.config["Exporter"]["Polling_Interval"])
        self.cisa_feed = requests.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")


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
        return int(hashlib.md5("{}".format(data).encode('utf-8')).hexdigest(),16)

    # time in seconds since unix epoch
    def create_timestamp(self):
        return int(datetime.datetime.now().timestamp())

    # converts csv download (in bytes) to dictionary
    def download_to_dict(self, download):
        StringIO_data = StringIO(str(download.content,'utf-8'))
        data_frame = pandas.read_csv(StringIO_data)
        return data_frame.to_dict(orient = "records")

    def construct_url(self, protocol, ip, port):
        return f"{protocol}://{ip}:{port}"

    # I don't want to store this information twice
    def exploited_cves(self):
        return [item["cveID"] for item in self.cisa_feed.json()["vulnerabilities"]]

    def in_cisa_feed(self, cve):
        return cve in self.exploited_cves()

    def benchmark(func):
        """
        A decorator that prints the time a function takes
        to execute.
        """
        import time

        def wrapper(*args, **kwargs):
            t1 = time.time()
            created, existed, size = func(*args, **kwargs)
            t2 = time.time() - t1
            results =(f"\n"
            f"Time (secs): {t2}\n"
            f"Size (bytes): {size}\n"
            f"Speed: {size/t2}\n"
            f"================================")
            return results, created, existed, size

        return wrapper

'''
ELKImporter inherits from Exporter Class
'''
class ELKImporter(Exporter):
    def __init__(self):
        super().__init__() #call the super-class' constructor
        # parse ELK related configuration
        self.elk_url = self.construct_url(self.config["ELK"]["Protocol"],self.config["ELK"]["IP"],self.config["ELK"]["Port"])
        self.elk_auth = self.config["ELK"]["Auth"]
        #self.elk = ELK(self.elk_url, self.elk_auth)

    def mappings(self):
        return  """ {
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
    def export_scan(self, nessus, elk, scan):
        import sys
        create_counter = 0
        exists_counter = 0
        data = self.download_to_dict(nessus.full_download(scan["id"]))
        scan_name = scan["name"].replace(" ", "_").lower()
        index = f"nessus_{scan_name}"
        resp = elk.set_mappings(index, self.mappings())
        for row in data:
            _id = self.md5_hash(row)
            if elk.document_exists(index, _id):
                exists_counter += 1
            else:
                create_counter += 1
                row["date"] = self.create_timestamp()
                row["in_cisa_feed"] = self.in_cisa_feed(row["CVE"])
                json = simplejson.dumps(row,ignore_nan=True)
                resp = self.elk.create_document(index, _id, json)


        return create_counter, exists_counter, sys.getsizeof(data)


'''
MongoImporter inherits from Exporter Class
'''
class MongoImporter(Exporter):
    def __init__(self):
        super().__init__() #call the super-class' constructor
        # parse Mongo related configuration
        self.mongo_url = self.config["Mongo"]["URL"]
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
