pub(crate) enum State {
    Closed,
    Listen,
    SynRcvd,
    Estab,
}

impl Default for State {
    fn default() -> Self {
        // For now, listen on every port. Eventually:
        // State::Closed
        State::Listen
    }
}

pub(crate) struct Connection {
    state: State,
}

/// State of the Send Sequence Space
///
///                   1         2          3          4
///              ----------|----------|----------|----------
///                     SND.UNA    SND.NXT    SND.UNA
///                                          +SND.WND
///
///        1 - old sequence numbers which have been acknowledged
///        2 - sequence numbers of unacknowledged data
///        3 - sequence numbers allowed for new data transmission
///        4 - future sequence numbers which are not yet allowed
pub(crate) struct SendSequencee {
    /// send unacknowledged
    una: usize,
    /// send next
    nxt: usize,
    /// send window
    wnd: usize,
    /// send urgent pointer
    up: bool,
    /// segment sequence number used for last window update
    wl1: usize,
    /// segment acknowledgement number used for last window update
    wl2: usize,
    /// initial send sequence number
    iss: usize,
}

impl Default for Connection {
    fn default() -> Self {
        Connection {
            state: <State as Default>::default(),
        }
    }
}

impl Connection {
    pub(crate) fn on_packet<'a>(
        &mut self,
        nic: &mut tun_tap::Iface,
        ip_header: etherparse::Ipv4HeaderSlice<'a>,
        tcp_header: etherparse::TcpHeaderSlice<'a>,
        body: &'a [u8],
    ) -> std::io::Result<()> {
        let to_write: [u8; 1500] = [0; 1500];
        eprintln!(
            "{}:{} - {}:{} {}b of tcp",
            ip_header.source_addr(),
            tcp_header.source_port(),
            ip_header.destination_addr(),
            tcp_header.destination_port(),
            body.len(),
        );
        match self.state {
            State::Closed => {
                return Ok(());
            }
            State::Listen => {
                if !tcp_header.syn() {
                    // only expected SYN packet
                    return Ok(());
                }

                // begin process of establishing a connection
                let mut syn_ack = etherparse::TcpHeader::new(
                    tcp_header.destination_port(),
                    tcp_header.source_port(),
                    unimplemented!(), // sequence number
                    unimplemented!(), // window size
                );
                syn_ack.ack = true;
                syn_ack.syn = true;
                let mut ip = etherparse::Ipv4Header::new(
                    syn_ack.header_len(),
                    64,
                    etherparse::IpNumber::Tcp,
                    ip_header.source_addr().octets(),
                    ip_header.destination_addr().octets(),
                );
                let unwritten = {
                    let mut unwritten = &mut to_write[..];
                    ip.write(&mut unwritten);
                    syn_ack.write(&mut unwritten)?;
                    unwritten.len()
                };
                nic.send(&to_write[..unwritten]).map(|_| ())
            }
            State::SynRcvd => unimplemented!(),
            State::Estab => unimplemented!(),
        }
    }
}
