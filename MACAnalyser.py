import ipaddress
import mysql.connector


class MACAnalyser:
    # Give MySql credentials, database name
    def __init__(self):
        self.mydb = mysql.connector.connect(host="localhost", user="cyber", passwd="1", database="logs_db")


    def get_user(self, mac_address, ip_pre_nat):
        ip_radius_lower_limit = int(ipaddress.ip_address('172.19.0.0'))
        ip_radius_upper_limit = int(ipaddress.ip_address('172.19.255.255'))
        ip_pre_nat_decimal = int(ipaddress.ip_address( ip_pre_nat))
        my_cursor = self.mydb.cursor()

        # Check radius log if ip address is in 172.19 subnet else check in contact info
        if ip_radius_lower_limit < ip_pre_nat_decimal < ip_radius_upper_limit:
            sql = "SELECT username from radacct where FramedIPAddress=%s and CallingStationId=%s"
            args = (ip_pre_nat, mac_address,)
            my_cursor.execute(sql, args)
            for user_name in my_cursor.fetchall():
                return user_name
        else:
            sql = "SELECT contact from contactinfo where mac_string=%s"
            args = (mac_address,)
            my_cursor.execute(sql, args)
            for user_name in my_cursor.fetchall():
                return user_name
