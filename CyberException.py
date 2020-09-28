class CyberException(Exception):
    pass


class NATException(CyberException):
    def __init__(self, ip):
        self.ip = ip
    pass


class DHCPException(CyberException):
    pass

