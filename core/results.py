class ScanResult:
    SERVICE_PORTS = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        443: "HTTP",
        110: "POP3",
        143: "IMAP",
        3306: "MySQL",
        1433: "MSSQL",
        3389: "RDP",
        8080: "HTTP",
    }

    def __init__(self, host, port, status, banner):
        self.host = host
        self.port = port
        self.status = status
        self.banner = banner
        self.service = self.SERVICE_PORTS.get(port, None)
