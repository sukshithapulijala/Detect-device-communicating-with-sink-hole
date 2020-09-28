import xml.etree.ElementTree as ET
import ipaddress
from datetime import datetime, timezone, timedelta, time
import pytz, ntpath
import os
import CyberException as CE
from IPy import IP

nat_log = ['nat.csv.2016032100.csv.gz', 'nat.csv.2016032101.csv.gz', 'nat.csv.2016032102.csv.gz'
           , 'nat.csv.2016032103.csv.gz', 'nat.csv.2016032104.csv.gz', 'nat.csv.2016032105.csv.gz'
           , 'nat.csv.2016032106.csv.gz', 'nat.csv.2016032107.csv.gz', 'nat.csv.2016032108.csv.gz'
           , 'nat.csv.2016032109.csv.gz', 'nat.csv.2016032110.csv.gz', 'nat.csv.2016032111.csv.gz'
           , 'nat.csv.2016032112.csv.gz', 'nat.csv.2016032113.csv.gz', 'nat.csv.2016032114.csv.gz'
           , 'nat.csv.2016032115.csv.gz', 'nat.csv.2016032116.csv.gz', 'nat.csv.2016032117.csv.gz'
           , 'nat.csv.2016032118.csv.gz', 'nat.csv.2016032119.csv.gz', 'nat.csv.2016032120.csv.gz'
           , 'nat.csv.2016032121.csv.gz', 'nat.csv.2016032122.csv.gz', 'nat.csv.2016032123.csv.gz'
           ]


class NATAnalyser:
    def __init__(self, xml_file_path, nat_log_folder_path):
        self.end_time = datetime.now()
        self.start_time = datetime.now()
        self.xml_file_path = xml_file_path
        self.xml_data = '0'
        self.nat_log_folder_path = nat_log_folder_path
        self.exact_local_time, self.local_dt = self.get_local_time_stamp()
        self.search_time = self.get_search_time_str(self.local_dt)
        self.nat_list = self.scan_nat_logs()
        self.ip_pre_nat, self.port_pre_nat, self.ip_remote, self.port_remote = self.get_arguments()
        self.date2 = ''
        self.timestamp = ''
        self.timestamp_lower=''

        try:
            IP(self.ip_pre_nat)
            IP(self.ip_remote)

        except Exception:
            ip_post_nat, ip_post_nat_decimal = self.get_post_nat_ip()
            raise CE.NATException(ip_post_nat)

    # Extract xml portion of text from the file
    # at xml_file_path then search for Infringement
    #
    def extract_xml(self):
        with open(self.xml_file_path, 'r') as file:
            data = file.read()
            xml_start = data.find('<?xml version="1.0" encoding="UTF-8"?>')
            xml_end = data.find('</Infringement>')
            self.xml_data = data[xml_start:xml_end+len('</Infringement>')]

    # Get the text part of XML tag
    #
    def get_xml_text(self, tag):
        self.extract_xml()
        root = ET.fromstring(self.xml_data)

        # Iterate to find <Source> and then the
        # text for passed in <tags>.
        for child in root:
            if 'Source' in child.tag:
                for item in child:
                    if tag in item.tag:
                        return item.text

    # Get post_nat_ip address from xml
    def get_post_nat_ip(self):
        ip_post_nat_text = self.get_xml_text('IP_Address')
        return ip_post_nat_text, int(ipaddress.ip_address(ip_post_nat_text))

    # Get post_nat_port from xml
    def get_post_nat_port(self):
        port_post_nat_text = self.get_xml_text('Port')
        return int(port_post_nat_text)

    # Get destination ip from xml
    def get_remote_ip(self):
        ip_remote_text = self.get_xml_text('Destination_IP')
        return int(ipaddress.ip_address(ip_remote_text))

    # Get remote port from xml
    def get_remote_port(self):
        port_remote_text = self.get_xml_text('Destination_Port')
        return int(port_remote_text)

    # Get local time
    def get_local_time_stamp(self):
        # Local timezone as eastern
        local_tz = pytz.timezone("America/New_York")

        # Get utc time from infringement xml
        utc_text = self.get_xml_text('TimeStamp')

        # Create datetime object from utc time stamp received in xml
        utc_dt = datetime.strptime(utc_text, '%Y-%m-%dT%H:%M:%SZ')
        local_dt = utc_dt.replace(tzinfo=pytz.utc).astimezone(local_tz)

        # Reformat and return
        return local_dt.strftime('%Y-%m-%dT%H:%M:%SZ'), local_dt

    @staticmethod
    def get_search_time_str(dt):
        return dt.strftime('%Y-%m-%dT%H:*')

    # Get nearest hour(s) and search for nat logs with those hours
    def get_nat_log_file_paths(self):
        self.end_time = (self.local_dt + timedelta(minutes=50))
        self.start_time = (self.local_dt - timedelta(minutes=30))

        files = [self.nat_log_folder_path + 'nat.csv.20160321' + str(self.start_time.hour) + '.csv.gz']
        if self.end_time.hour != self.start_time.hour:
            files.append(self.nat_log_folder_path + 'nat.csv.20160321' + str(self.end_time.hour) + '.csv.gz')
        return files

    # Scan the nat logs
    def scan_nat_logs(self):
        ip_post_nat, ip_post_nat_decimal = self.get_post_nat_ip()
        port_post_nat = self.get_post_nat_port()
        files_to_scan = self.get_nat_log_file_paths()

        # Create command used to scan nat logs
        #
        for file in files_to_scan:
            tail = ntpath.basename(file)
            pre_nat_find_cmd = "zgrep \"{}\" {} | grep \"{},{}\""\
                .format(self.search_time, file, ip_post_nat, port_post_nat)
            print("Searching NAT log @ %s" % tail)

            op = os.popen(pre_nat_find_cmd).read()
            nat_list = op.splitlines()
        return nat_list

    # Retrieve the required arguments like pre_nat_ip, post_nat_ip, ip_remote and port_remote to search in DHCP tables.
    def get_arguments(self):
        ip_pre_nat = ''
        port_pre_nat = ''
        ip_remote = ''
        port_remote = ''
        for args in self.nat_list:
            args = args.split(',')

            date = args[0]
            date1 = datetime.strptime(date[0:19], '%Y-%m-%dT%H:%M:%S')
            self.date2 = date1.strftime('%Y-%m-%dT%H:%M:%SZ')

            self.timestamp = date1.strftime("%s")
            timestamp_int = int(self.timestamp)
            self.timestamp_lower = (str(timestamp_int-20))

            # Search for +/-10 mins of given time
            lower = datetime.strftime((self.local_dt - timedelta(minutes=10)), '%Y-%m-%dT%H:%M:%SZ')
            upper = datetime.strftime((self.local_dt + timedelta(minutes=10)), '%Y-%m-%dT%H:%M:%SZ')
            if lower < self.date2 < upper:
                ip_pre_nat = args[2]
                port_pre_nat = args[3]
                ip_remote = args[4]
                port_remote = args[5]
                break
        return ip_pre_nat, port_pre_nat, ip_remote, port_remote

    def get_pre_nat_ip(self):
        return self.ip_pre_nat

    def get_pre_nat_port(self):
        return self.port_pre_nat

    def get_remote_ip(self):
        return self.ip_remote

    def get_remote_port(self):
        return self.port_remote

    def get_timestamp(self):
        return self.timestamp

    def get_timestamp_lower(self):
        return self.timestamp_lower

    def get_start_end_time(self):
        return self.start_time, self.end_time
