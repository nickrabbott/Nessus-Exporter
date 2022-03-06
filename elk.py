from secrets import secrets
import json
import simplejson
import requests
import hashlib
import datetime

class ELK:
    def __init__(self, url, auth):
        self.url = url
        self.headers = {
            'Content-Type': 'application/json',
            'Authorization': auth
        }

    # accepts string, returns md5 int, no error handling
    def md5_hash(self, data):
        return int(hashlib.md5(data.encode('utf-8')).hexdigest(),16)

    # time in seconds since unix epoch
    def create_timestamp(self):
        return int(datetime.datetime.now().timestamp())

    # set the date field datatype for the index parameter
    def set_datatypes(self, index):
        json_data = """ {
                          "mappings": {
                            "properties": {
                              "date": {
                                "type":   "date",
                                "format": "epoch_second"
                              }
                            }
                          }
                        }"""
        return requests.put('{}/{}'.format(self.url, index), headers=self.headers, data = json_data, verify=False).json()

    def document_exists(self, index, _id):
        uri = '{}/{}/_doc/{}'.format(self.url, index, _id)
        response = requests.get(uri, headers=self.headers, verify=False).json()
        try:
            if response["found"] == True:
                return True
            elif response["found"] == False:
                return False
            else:
                return response
        except Exception as err:
            return False

    def create_document(self, index, _id, json):
        uri = '{}/{}/_create/{}'.format(self.url, index, _id)
        response = requests.put(uri, headers=self.headers, data=json, verify=False)
        return response.json()

    def insert_document(self,dict,index):
        _id = self.md5_hash("{}".format(dict))
        if self.document_exists(index, _id) is False:
            date = self.create_timestamp()
            dict["date"] = date
            json_data = simplejson.dumps(dict,ignore_nan=True)
            resp = self.create_document(index, _id, json_data)
            uri = '{}/{}/_doc/{}'.format(self.url, index, _id)
            response = requests.put(uri, headers=self.headers, data=json_data, verify=False)
            return response.json()
        else:
            return None
