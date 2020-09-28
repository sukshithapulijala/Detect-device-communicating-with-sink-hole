import ipaddress
import mysql.connector
import pytz, datetime
import CyberException as CE


class DHCPAnalyser:
    # Connect to MySql
    def __init__(self):
        self.mydb = mysql.connector.connect(host="localhost", user="cyber", passwd="1", database="logs_db")

    # Search in DHCP table for ip and mac address for the pre nat ip and timestamps receives from NATAnalyser.
    def get_mac_addr(self, ip_pre_nat, timestamp_lower, timestamp):
        my_cursor = self.mydb.cursor()
        sql = """SELECT ip_decimal,mac_string,pc_name,transaction,timestamp FROM dhcp where ip_decimal=%s and %s < timestamp and %s > timestamp"""
        arg = (int(ipaddress.ip_address(ip_pre_nat)), timestamp_lower, timestamp)

        my_cursor.execute(sql, arg)
        result_set = my_cursor.fetchall()
        if len(result_set) != 0:
            for row in result_set:
                ip = row[0]
                mac = row[1]
                break
            return ip, mac
        else:
            raise CE.DHCPException

