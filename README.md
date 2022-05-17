# Nessus Exporter

Nessus Exporter is an automation tool in Python that automates the export of [Nessus Vulnerability Scans](https://www.tenable.com/) to be imported into an Analytics Platform. Currently, this works with [Elastic Search](https://www.elastic.co/) and [MongoDB Atlas](https://www.mongodb.com/atlas/database), but I may extend functionality with other NoSQL platforms such as [Splunk](https://www.splunk.com/) or [DynamoDB](https://aws.amazon.com/dynamodb/).

## Installation
Use the package manager [pip](https://pip.pypa.io/en/stable/) to install the following packages.

```bash
pip install simplejson
pip install pandas
```
For systemd based systems, clone the repo under /etc
```bash
git clone git@github.com:nickrabbott/Nessus-Exporter.git
or
git clone https://github.com/nickrabbott/Nessus-Exporter.git
```
Fill in the appropriate values in /config/config.ini. Polling_Interval is in seconds.
```ini
[DEFAULT]

[Exporter]
Polling_Interval = 86400

[NESSUS]
Protocol = https
IP = 0.0.0.0
Port = 8834
Secret_Key = nessus_secret_key
Access_Key = nessus_access_key

[ELK]
Protocol = https
IP = 0.0.0.0
Port = 9201
Auth = Basic_Auth

[Mongo]
URL = "mongodb atlas url"
```
Modify the systemd unit file under /config to store the appropriate values and remove the .sample extension.
```ini
[Unit]
Description=Nessus Exporter Service
After=network.target
After=elasticsearch.service
After=kibana.service
After=nessusd.service

[Service]
WorkingDirectory=/etc/nessus-exporter/src/
User=nick
Type=simple
ExecStart=/usr/bin/python3 -u /etc/nessus-exporter/src/nessusexporter.py

[Install]
WantedBy=multi-user.target
```
Create a symbolic link to the unit file in /etc/systemd/system
```
sudo ln -s /etc/systemd/nessus-exporter.service /etc/nessus-exporter/config/nessus-exporter.service
```
## Usage
Make systemd aware of the new unit file
```bash
sudo systemctl daemon-reload
```
Start the service
```bash
sudo systemctl start nessus-exporter.service
```
Check the status of the service
```bash
sudo systemctl status nessus-exporter.service
● nessus-exporter.service - Nessus Exporter Service
   Loaded: loaded (/etc/nessus-exporter/config/nessus-exporter.service; linked; vendor preset: enabled)
   Active: active (running) since Wed 2022-03-16 00:41:01 UTC; 39min ago
 Main PID: 21837 (python3)
    Tasks: 1 (limit: 4656)
   CGroup: /system.slice/nessus-exporter.service
           └─21837 /usr/bin/python3 -u /etc/nessus-exporter/src/nessusexporter.py

```
View the logs associated with the service
```bash
sudo journalctl -u nessus-exporter.service
```
## Contributing
Feel free to fork this repo or submit a pull request
## License
[MIT](LICENSE)