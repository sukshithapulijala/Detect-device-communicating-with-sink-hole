from NATAnalyser import NATAnalyser
from DHCPAnalyser import DHCPAnalyser
from MACAnalyser import MACAnalyser
from IPy import IP
import CyberException as CE
from os import listdir
from os.path import isfile, join
import ntpath, os


def main(path):
    test_cases = path

    # Get the path for the current file: main.py
    find_path = os.path.dirname(os.path.realpath(__file__))

    # move to the parent folder where we have nat log files and test cases
    found_nat_logs = False
    while not found_nat_logs:
        for root, directory, files in os.walk(find_path):
            for dir in directory:
                if dir == 'nat_logs':
                    found_nat_logs = True
                    # create path to nat_logs
                    nat_logs_path = find_path + '/' + dir + '/'
        find_path = os.path.dirname(find_path)

    only_files = []
    notices = []
    # listing all notices in test_cases folder
    for f in listdir(test_cases):
        if isfile(join(test_cases, f)):
            only_files.append(f)
            notices.append(join(test_cases, f))
    print("below are the testcases:")
    print(only_files)
    print()
    # search infected users for each notice
    for notice in notices:
        try:
            print("Processing: %s" % ntpath.basename(notice))

            my_nat_als = NATAnalyser(notice, nat_logs_path)

            my_dhcp_als = DHCPAnalyser()

            start_time, end_time = my_nat_als.get_start_end_time()
            ip_addr, mac_addr = my_dhcp_als.get_mac_addr(my_nat_als.get_pre_nat_ip(), start_time, end_time)

            IP(ip_addr)
            my_mac_als = MACAnalyser()
            user_name = my_mac_als.get_user(mac_addr, my_nat_als.get_pre_nat_ip())

            print("Infected user %s with mac address %s" %(user_name, mac_addr))
            print()

        # Handle false positive exceptions
        except CE.NATException as NATExcep:
            print("%s Not found in above log files\n" % NATExcep.ip)
        except CE.DHCPException:
            print("")


if __name__ == "__main__":
    main(os.sys.argv[1])



