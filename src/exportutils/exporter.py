from io import StringIO
import hashlib
import pandas
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



'''
ELKImporter inherits from Exporter Class
'''
class ELKImporter(Exporter):
    def __init__(self):
        super().__init__() #call the super-class' constructor
        # parse ELK related configuration
        self.elk_url = self.construct_url(self.config["ELK"]["Protocol"],self.config["ELK"]["IP"],self.config["ELK"]["Port"])
        self.elk_auth = self.config["ELK"]["Auth"]

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

    def export_scan(self, nessus, elk, scan):
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
