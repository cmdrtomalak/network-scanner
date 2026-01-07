use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Connection {
    pub protocol: String,
    pub local_addr: IpAddr,
    pub local_port: u16,
    pub remote_addr: Option<IpAddr>,
    pub remote_port: Option<u16>,
    pub state: String,
    pub pid: Option<u32>,
    pub process_name: Option<String>,
    pub is_inbound: bool,
}

impl Connection {
    pub fn format_local(&self) -> String {
        format!("{}:{}", self.local_addr, self.local_port)
    }

    pub fn format_remote(&self) -> String {
        match (self.remote_addr, self.remote_port) {
            (Some(addr), Some(port)) => format!("{}:{}", addr, port),
            _ => "*:*".to_string(),
        }
    }

    pub fn service_name(&self) -> Option<&'static str> {
        get_service_name(self.local_port)
    }
}

pub fn get_service_name(port: u16) -> Option<&'static str> {
    match port {
        20 => Some("ftp-data"),
        21 => Some("ftp"),
        22 => Some("ssh"),
        23 => Some("telnet"),
        25 => Some("smtp"),
        53 => Some("dns"),
        67 => Some("dhcp-server"),
        68 => Some("dhcp-client"),
        69 => Some("tftp"),
        80 => Some("http"),
        110 => Some("pop3"),
        119 => Some("nntp"),
        123 => Some("ntp"),
        135 => Some("msrpc"),
        137 => Some("netbios-ns"),
        138 => Some("netbios-dgm"),
        139 => Some("netbios-ssn"),
        143 => Some("imap"),
        161 => Some("snmp"),
        162 => Some("snmptrap"),
        389 => Some("ldap"),
        443 => Some("https"),
        445 => Some("microsoft-ds"),
        465 => Some("smtps"),
        514 => Some("syslog"),
        515 => Some("printer"),
        587 => Some("submission"),
        631 => Some("ipp"),
        636 => Some("ldaps"),
        873 => Some("rsync"),
        993 => Some("imaps"),
        995 => Some("pop3s"),
        1080 => Some("socks"),
        1433 => Some("mssql"),
        1434 => Some("mssql-m"),
        1521 => Some("oracle"),
        1723 => Some("pptp"),
        2049 => Some("nfs"),
        2082 => Some("cpanel"),
        2083 => Some("cpanel-ssl"),
        2181 => Some("zookeeper"),
        3000 => Some("dev-server"),
        3306 => Some("mysql"),
        3389 => Some("rdp"),
        4443 => Some("pharos"),
        5000 => Some("upnp"),
        5432 => Some("postgresql"),
        5672 => Some("amqp"),
        5900 => Some("vnc"),
        6379 => Some("redis"),
        6443 => Some("kubernetes"),
        8000 => Some("http-alt"),
        8080 => Some("http-proxy"),
        8443 => Some("https-alt"),
        8888 => Some("http-alt2"),
        9000 => Some("cslistener"),
        9090 => Some("zeus-admin"),
        9200 => Some("elasticsearch"),
        9418 => Some("git"),
        11211 => Some("memcached"),
        27017 => Some("mongodb"),
        _ => None,
    }
}
