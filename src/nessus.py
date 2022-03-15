import requests
import time

class Nessus:
    def __init__(self, access_key, secret_key, url):
        self.access_key = access_key
        self.secret_key = secret_key
        self.headers = {'accept': 'application/json',
                    'x-apikeys': f"accessKey={self.access_key};secretKey={self.secret_key}"
    	}
        self.url = url
        self.scan_data = '{"format":"csv","template_id":"","reportContents":{"csvColumns":{"id":true,"cve":true,"cvss":true,"risk":true,"hostname":true,"protocol":true,"port":true,"plugin_name":true,"synopsis":true,"description":true,"solution":true,"see_also":true,"plugin_output":true,"stig_severity":false,"cvss3_base_score":false,"cvss_temporal_score":false,"cvss3_temporal_score":false,"risk_factor":false,"references":false,"plugin_information":false,"exploitable_with":false}},"extraFilters":{"host_ids":[],"plugin_ids":[]}}'

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
        url = f"{self.url}/scans/{id}"
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

    def last_modification_date(self, id):
        scan_details = self.get_scan_details(id)
        return scan_details["history"][0]["last_modification_date"]

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

    def export_scan(self, id, payload=None):
        url = f"{self.url}/scans/{id}/export"
        h = self.headers
        if payload == None:
            payload = self.scan_data
        h["Content-Type"] = "application/json"
        return requests.request("POST", url, data=payload, headers=h, verify=False).json()

    def export_status(self, id, file_id):
        url = f"{self.url}/scans/{id}/export/{file_id}/status"
        return requests.request("GET", url, headers=self.headers, verify=False).json()

    def export_download(self, id, file_id):
        url = f"{self.url}/scans/{id}/export/{file_id}/download"
        return requests.request("GET", url, headers=self.headers, verify=False)

    def full_download(self, id, columns=None):
        if columns == None:
            columns = self.scan_data
        export_response = self.export_scan(id, columns)
        export_status = self.export_status(id, export_response["file"])
        while export_status['status'] != "ready":
            time.sleep(2)
            export_status = self.export_status(id, export_response["file"])

        return self.export_download(id, export_response["file"])
