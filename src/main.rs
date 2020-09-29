use std::net::SocketAddr;
use std::str::FromStr;
use std::thread;

use std::net::IpAddr;

use neli::consts::{Rtm, RtTable, Rta, NlFamily, RtAddrFamily, Rtprot, RtScope, Rtn, NlmF};
use neli::nl::Nlmsghdr;
use neli::rtnl::{Rtmsg, Rtattrs};
use neli::socket::NlSocket;
use structopt::StructOpt;
use trust_dns_client::client::{Client, SyncClient};
use trust_dns_client::udp::UdpClientConnection;
use trust_dns_client::rr::{DNSClass, Name, RData, Record, RecordType};

const SERVERS: [&str; 5] = [
    "1.1.1.1", // Cloudflare
    "8.8.8.8", // Google DNS
    "9.9.9.9", // Quad9
    "37.235.1.174", // FreeDNS
    "208.67.222.222" // OpenDNS
];

#[derive(Debug, StructOpt)]
#[structopt(name = "MDQ: Multi DNS Query", about = "Query a name from multiple DNS servers.")]
struct Opt {
    #[structopt(short = "n", long = "name")]
    name: String,
}

// via https://github.com/jbaublitz/neli/blob/master/examples/route-list.rs
fn get_default_route(rtm: Nlmsghdr<Rtm, Rtmsg>) -> Option<IpAddr> {
    if rtm.nl_payload.rtm_table != RtTable::Main {
        return None
    }

    let mut gateway = None;

    for attr in rtm.nl_payload.rtattrs.iter() {
        fn to_addr(b: &[u8]) -> Option<IpAddr> {
            use std::convert::TryFrom;
            if let Ok(tup) = <&[u8; 4]>::try_from(b) {
                Some(IpAddr::from(*tup))
            } else if let Ok(tup) = <&[u8; 16]>::try_from(b) {
                Some(IpAddr::from(*tup))
            } else {
                None
            }
        }

        match attr.rta_type {
            Rta::Gateway => gateway = to_addr(&attr.rta_payload),
            _ => (),
        }
    }

    return gateway;
}

// via https://github.com/jbaublitz/neli/blob/master/examples/route-list.rs
fn get_default_gateway() -> Option<IpAddr> {
    let mut socket = NlSocket::connect(NlFamily::Route, None, None, true).unwrap();

    let rtmsg = Rtmsg {
        rtm_family: RtAddrFamily::Inet,
        rtm_dst_len: 0,
        rtm_src_len: 0,
        rtm_tos: 0,
        rtm_table: RtTable::Unspec,
        rtm_protocol: Rtprot::Unspec,
        rtm_scope: RtScope::Universe,
        rtm_type: Rtn::Unspec,
        rtm_flags: vec![],
        rtattrs: Rtattrs::empty(),
    };
    let nlhdr = {
        let len = None;
        let nl_type = Rtm::Getroute;
        let flags = vec![NlmF::Request, NlmF::Dump];
        let seq = None;
        let pid = None;
        let payload = rtmsg;
        Nlmsghdr::new(len, nl_type, flags, seq, pid, payload)
    };
    socket.send_nl(nlhdr).unwrap();

    let nl = socket.recv_nl::<Rtm, Rtmsg>(None).unwrap();
    return get_default_route(nl);
}

fn get_rrs(name: &str, server: IpAddr) {
    let server_address = format!("{}:53", server).parse::<SocketAddr>().unwrap();
    let conn = UdpClientConnection::new(server_address).unwrap();
    let client = SyncClient::new(conn);

    let fqdn = if !name.ends_with(".") {
        format!("{}.", name)
    } else {
        name.to_string()
    };

    let fqdn_name = Name::from_str(&fqdn).unwrap();

    let maybe_response = client.query(&fqdn_name, DNSClass::IN, RecordType::A);

    if maybe_response.is_err() {
        println!("{}: Error {}", server, maybe_response.clone().err().unwrap())
    }

    let response = maybe_response.unwrap();

    let answers: &[Record] = response.answers();

    if answers.len() == 0 {
        println!("{}: No response", server);
        return
    }

    for answer in answers {
        if let &RData::A(ref ipv4) = answer.rdata() {
            println!("{}: IPv4 {}", server, ipv4)
        } else if let &RData::CNAME(ref canonical) = answer.rdata() {
            println!("{}: CNAME {}", server, canonical);
        }
    }
}

fn main() {
    let opt = Opt::from_args();
    let gateway = get_default_gateway();

    let mut servers: Vec<IpAddr> = vec![];
    let mut handles = vec![];

    for s in SERVERS.iter() {
        servers.push(IpAddr::from_str(s).unwrap());
    }

    if gateway.is_some() {
        servers.push(gateway.unwrap());
    }

    for server in servers {
        let name = opt.name.clone();
        let handle = thread::spawn(move || {
            get_rrs(&name, server)
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }
}
