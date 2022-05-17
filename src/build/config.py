import ipaddress
import configparser

def validate_ip(address):
    try:
        ip = ipaddress.ip_address(address)

        if isinstance(ip, ipaddress.IPv4Address):
            return True
        elif isinstance(ip, ipaddress.IPv6Address):
            print("IPv6 not currently supported")
            return False
    except ValueError:
        if address == "localhost":
            return True
        else:
            return False


def validate_port(port):
    return (port < 0) or (port > 65535)


class Config:
    def __init__(self, config_file):
        self.config_parser = configparser.ConfigParser()
        self.config_parser.read(config_file)
        config_dict = {s:dict(self.config_parser.items(s)) for s in self.config_parser.sections()}
        self.nessus_config = config_dict.get("NESSUS", None)
        self.exporter_config = config_dict.get("Exporter", None)
        self.elk_config = config_dict.get("ELK", None)
        self.mongo_config = config_dict.get("Mongo", None)

    def validate_config(self):
        # These must be valid
        if self.validate_nessus_config() is False:
            return False
        elif self.validate_exporter_config() is False:
            return False

        elk_validity = False
        mongo_validity = False
        
        if self.elk_config is not None:
            elk_validity = self.validate_elk_config()
        if self.mongo_config is not None:
            mongo_validity = self.validate_mongo_config()

        return (elk_validity or mongo_validity)

    '''
        returns true if exporter config is valid,
        otherwise false
    '''
    def validate_exporter_config(self):
        polling_interval = self.exporter_config.get("polling_interval", False)
        if polling_interval == "":
            polling_interval = False
            print("Set the polling interval greater than or equal to 20 minutes (1200 seconds)")
        elif int(polling_interval) < 1200:
            print("Not recommended to set a polling interval less than 20 minutes (1200 seconds)")

        return polling_interval


    '''
        returns true if nessus config is valid,
        otherwise false
    '''
    def validate_nessus_config(self):
        protocol = self.nessus_config.get("protocol", False)
        if protocol != "https":
            protocol = False

        ip = self.nessus_config.get("ip", False)
        ip = validate_ip(ip)

        port = self.nessus_config.get("port", False)
        if (port != False) and validate_port(int(port)):
            port = False

        access_key = self.nessus_config.get("access_key", False)
        secret_key = self.nessus_config.get("secret_key", False)

        return (protocol and ip and port and access_key and secret_key)

    '''
        returns true if nessus config is valid,
        otherwise false
    '''
    def validate_elk_config(self):
        protocol = self.elk_config.get("protocol", False)
        if protocol != "https":
            protocol = False

        ip = self.elk_config.get("ip", False)
        ip = validate_ip(ip)

        port = self.elk_config.get("port", False)
        if (port != False) and validate_port(int(port)):
            port = False

        auth = self.elk_config.get("auth", False)

        return (protocol and ip and port and auth)


    '''
        returns true if nessus config is valid,
        otherwise false
    '''
    def validate_mongo_config(self):
        url = self.mongo_config.get("url", False)
        if url != False:
            url = True

        return url
