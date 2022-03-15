from nessus import Nessus
from elk import ELK
from io import StringIO
import hashlib
import pandas
import datetime
import simplejson
import configparser
import time
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

'''
The Exporter class stores the state and history of exports
'''
class Exporter:
    def __init__(self):
        self.indexes = []
        self.index_history = {}
        self.polling_interval = 43200 # default value 1 day, overriden by config.ini

    def get_indexes(self):
        return self.indexes

    def get_index_history(self, index):
        return self.index_history[index]

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

    # need to find a better way of parsing the config to separate
    # nonexclusive information from the Exporter class (i.e. ELK, MongoDB, SQL, whatever)
    def parse_config(self):
        config = configparser.ConfigParser()
        config.read("../config/config.ini")
        config.sections()
        self.polling_interval = int(config["Exporter"]["Polling_Interval"])
        nessus_url = self.construct_url(config["NESSUS"]["Protocol"],config["NESSUS"]["IP"],config["NESSUS"]["Port"])
        elk_url = self.construct_url(config["ELK"]["Protocol"],config["ELK"]["IP"],config["ELK"]["Port"])
        nessus_access_key = config["NESSUS"]["Access_Key"]
        nessus_secret_key = config["NESSUS"]["Secret_Key"]
        elk_auth = config["ELK"]["Auth"]
        return nessus_url, elk_url, nessus_access_key, nessus_secret_key, elk_auth


'''
ELKImporter inherits from Exporter Class
'''
class ELKImporter(Exporter):
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

    def export_scan(self, scan):
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
                json = simplejson.dumps(row,ignore_nan=True)
                resp = elk.create_document(index, _id, json)

        return create_counter, exists_counter



if __name__ == "__main__":
    exporter = ELKImporter()
    nessus_url, elk_url, nessus_access_key, nessus_secret_key, elk_auth = exporter.parse_config()
    nessus = Nessus(nessus_access_key, nessus_secret_key, nessus_url)
    elk = ELK(elk_url, elk_auth)
    while True:
        for scan in nessus.get_scans():
            if scan["name"] not in exporter.get_indexes():
                exporter.add_index(scan['name'], nessus.last_modification_date(scan["id"]))
                created, existed = exporter.export_scan(scan)
                print(f"{scan['name']}: Created: {created}. Unchanged: {existed}")
            elif (scan["name"] in exporter.get_indexes()) and (nessus.last_modificacation_date(scan["id"]) != exporter.get_index_history(scan["name"]) ):
                exporter.update_history(scan['name'], nessus.last_modificacation_date(scan["id"]))
                created, existed = exporter.export_scan(scan)
                print(f"{scan['name']}: Created: {created}. Unchanged: {existed}")
            else:
                print(f"{scan['name']} has no updates.")

        time.sleep(exporter.polling_interval)
