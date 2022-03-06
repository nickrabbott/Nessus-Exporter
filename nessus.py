import requests
import time
import pandas
from elk import ELK
from secrets import secrets


class Nessus:
    def __init__(self, access_key, secret_key, url):
        self.access_key = access_key
        self.secret_key = secret_key
        self.headers = {'accept': 'application/json',
                    'x-apikeys': "accessKey={};secretKey={}".format(self.access_key,self.secret_key)
    	}
        self.url = url

    def server_status(self):
        url = self.url + "/server/status"
        return requests.request("GET", url, headers=self.headers, verify=False).json()

    def get_scans(self):
        url = self.url + "/scans"
        response = requests.request("GET", url, headers=self.headers, verify=False).json()
        return response["scans"]

    def scan_exists(self, name):
        scans = self.get_scans()
        if not any(s['name'] == name for s in scans):
            return "Scan not found"
        else:
            return "Scan found"

    def get_scan_details(self, id):
        url = "{}/scans/{}".format(self.url, id)
        return requests.request("GET", url, headers=self.headers, verify=False).json()

    def get_info(self, id):
        scan_details = self.get_scan_details(id)
        return scan_details["info"]

    def get_compliance(self, id):
        scan_details = self.get_scan_details(id)
        return scan_details["compliance"]

    def get_filters(self, id):
        scan_details = self.get_scan_details(id)
        return scan_details["filters"]

    def get_comphosts(self, id):
        scan_details = self.get_scan_details(id)
        return scan_details["comphosts"]

    def get_history(self, id):
        scan_details = self.get_scan_details(id)
        return scan_details["history"]

    def get_notes(self, id):
        scan_details = self.get_scan_details(id)
        return scan_details["notes"]

    def get_hosts(self, id):
        scan_details = self.get_scan_details(id)
        return scan_details["hosts"]

    def get_remediations(self, id):
        scan_details = self.get_scan_details(id)
        return scan_details["remediations"]

    def get_prioritization(self, id):
        scan_details = self.get_scan_details(id)
        return scan_details["prioritization"]

    def get_vulnerabilities(self, id):
        scan_details = self.get_scan_details(id)
        return scan_details["vulnerabilities"]

    def export_scan(self, id):
        url = "{}/scans/{}/export".format(self.url, id)
        h = self.headers
        h["Content-Type"] = "application/json"
        payload = '{"format":"csv","template_id":"","reportContents":{"csvColumns":{"id":true,"cve":true,"cvss":true,"risk":true,"hostname":true,"protocol":true,"port":true,"plugin_name":true,"synopsis":true,"description":true,"solution":true,"see_also":true,"plugin_output":true,"stig_severity":false,"cvss3_base_score":false,"cvss_temporal_score":false,"cvss3_temporal_score":false,"risk_factor":false,"references":false,"plugin_information":false,"exploitable_with":false}},"extraFilters":{"host_ids":[],"plugin_ids":[]}}'
        return requests.request("POST", url, data=payload, headers=h, verify=False).json()

    def export_status(self, id, file_id):
        url = "{}/scans/{}/export/{}/status".format(self.url, id, file_id)
        return requests.request("GET", url, headers=self.headers, verify=False).json()

    def export_download(self, id, file_id):
        url = "{}/scans/{}/export/{}/download".format(self.url, id, file_id)
        return requests.request("GET", url, headers=self.headers, verify=False)

    def full_download(self, id):
        export_response = self.export_scan(id)
        export_status = self.export_status(id, export_response["file"])
        while export_status['status'] != "ready":
            time.sleep(2)
            export_status = self.export_status(id, export_response["file"])

        return self.export_download(id, export_response["file"])


if __name__ == '__main__':
    url = secrets.get("NESSUS_URL")
    access_key = secrets.get("NESSUS_ACCESS_KEY")
    secret_key = secrets.get("NESSUS_SECRET_KEY")
    nessus = Nessus(access_key, secret_key, url)

    elk = ELK(secrets.get("ELK_URL"), secrets.get("ELK_AUTH"))

    for scan in nessus.get_scans():
        download = nessus.full_download(scan["id"])
        filename = "{}{}".format(scan["name"], ".csv")
        with open(filename, "wb") as fobject:
            fobject.write(download.content)

        data_frame = pandas.read_csv(filename)
        data = data_frame.to_dict(orient = "records")
        index = "nessus_{}".format(scan["name"].replace(" ", "_").lower())
        resp = elk.set_datatypes(index)
        for row in data:
            response = elk.insert_document(row, index)
