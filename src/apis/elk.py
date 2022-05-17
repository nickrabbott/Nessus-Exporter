import requests


class ELK:
    def __init__(self, url, auth):
        self.url = url
        self.headers = {
            'Content-Type': 'application/json',
            'Authorization': auth
        }

    def set_mappings(self, index, json_datatypes):
        return requests.put(f'{self.url}/{index}', headers=self.headers, data=json_datatypes, verify=False).json()

    def document_exists(self, index, _id):
        uri = f'{self.url}/{index}/_doc/{_id}'
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
        uri = f'{self.url}/{index}/_create/{_id}'
        response = requests.put(uri, headers=self.headers, data=json, verify=False)
        return response.json()
