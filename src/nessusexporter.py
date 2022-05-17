import concurrent.futures
from apis import *
from build import *
import time
import sys


config = Config("../config/config.ini")
nessus = Nessus(f"{config.nessus_config.get('access_key')}", f"{config.nessus_config.get('secret_key')}", f"{config.nessus_config.get('protocol')}://{config.nessus_config.get('ip')}:{config.nessus_config.get('port')}")

if not config.validate_config():
    print("Invalid configuration")
    sys.exit(1)
elif config.elk_config is not None:
    exporter = ELKImporter(exporter_config=config.exporter_config, nessus_config=config.nessus_config, elk_config=config.elk_config)
    print("created ELK Importer")
elif config.mongo_config is not None:
    exporter = MongoImporter(exporter_config=config.exporter_config, nessus_config=config.nessus_config, mongo_config=config.mongo_config)
    print("created Mongo Importer")



def process_scan(scan):
    nessus_lmd = nessus.last_modification_date(scan["id"])
    exporter_lmd = exporter.get_index_history(scan["name"])
    if scan["name"] not in exporter.get_indexes():
        exporter.add_index(scan['name'], nessus_lmd)
        created, existed, benchmark = exporter.export_scan(nessus, scan)
        print(f"{scan['name']}: Created: {created}. Unchanged: {existed}. Time: {benchmark}")
    elif (scan["name"] in exporter.get_indexes()) and (nessus_lmd != exporter_lmd):
        exporter.update_history(scan['name'], nessus_lmd)
        created, existed, benchmark = exporter.export_scan(nessus, scan)
        print(f"{scan['name']}: Created: {created}. Unchanged: {existed}. Time: {benchmark}")
    else:
        print(f"{scan['name']} has no updates.")


if __name__ == "__main__":
    while True:
        t1 = time.time()
        # single thread:
        # for scan in nessus.get_scans():
        #     process_scan(scan)
        #     break
        with concurrent.futures.ThreadPoolExecutor() as executor:
            executor.map(process_scan, nessus.get_scans())
    
        print(f"Total Time: {time.time() - t1}. Sleeping for {exporter.polling_interval} seconds.")
        time.sleep(exporter.polling_interval)
