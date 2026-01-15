#![allow(dead_code)]
use crate::config;
use quiche::h3::NameValue;
use rand::RngCore;
use std::{collections::HashMap, net::SocketAddr};

pub mod http;

pub struct Client {
    in_flight: HashMap<u64, InFlight>, // maps stream_id to sent request
    conn_quic: quiche::Connection,
    conn_h3: Option<quiche::h3::Connection>,
    socket: mio::net::UdpSocket,
    poll: mio::Poll,
    events: mio::Events,
}

impl Client {
    pub fn new(args: config::QuicConfig) -> anyhow::Result<Self> {
        // initialize udp socket
        let mut socket = mio::net::UdpSocket::bind("0.0.0.0:0".parse().unwrap())?;

        // setup event loop using mio
        let mut poll = mio::Poll::new()?;
        let mut events = mio::Events::with_capacity(1024);

        poll.registry()
            .register(
                &mut socket,
                mio::Token(0),
                mio::Interest::READABLE | mio::Interest::WRITABLE,
            )
            .unwrap();

        // setup QUIC config
        let mut config_quic = quiche::Config::new(quiche::PROTOCOL_VERSION)?;

        config_quic.verify_peer(args.verify_peer);
        config_quic.set_application_protos(quiche::h3::APPLICATION_PROTOCOL)?;
        config_quic.set_max_recv_udp_payload_size(config::MAX_DATAGRAM_SIZE);
        config_quic.set_max_send_udp_payload_size(config::MAX_DATAGRAM_SIZE);
        config_quic.set_initial_max_data(10_000_000);
        config_quic.set_initial_max_stream_data_bidi_local(1_000_000);
        config_quic.set_initial_max_stream_data_bidi_remote(1_000_000);
        config_quic.set_initial_max_stream_data_uni(1_000_000);
        config_quic.set_initial_max_streams_bidi(100);
        config_quic.set_initial_max_streams_uni(100);
        config_quic.set_disable_active_migration(true);
        config_quic.set_max_idle_timeout(5000);

        // determine SCID
        let mut scid_bytes = [0u8; quiche::MAX_CONN_ID_LEN];
        rand::rng().fill_bytes(&mut scid_bytes);
        let scid = quiche::ConnectionId::from_ref(&scid_bytes);

        // define peer address
        let peer = SocketAddr::V4(args.remote_addr);
        // define local address from socket
        let local = socket.local_addr()?;

        log::info!(
            "connecting to {:} from {:?} with scid {}",
            peer,
            &socket.local_addr()?,
            hex_dump(&scid)
        );

        // establish quic connection
        let mut conn_quic = quiche::connect(
            Some(&args.server_name),
            &scid,
            local,
            peer,
            &mut config_quic,
        )?;

        // perform handshake
        Self::perform_handshake(&mut conn_quic, &mut socket, &mut poll, &mut events)?;

        log::info!(
            "quic connection established? {}",
            conn_quic.is_established()
        );

        let in_flight: HashMap<u64, InFlight> = HashMap::new();

        Ok(Self {
            poll,
            events,
            socket,
            conn_quic,
            conn_h3: None,
            in_flight,
        })
    }

    fn perform_handshake(
        conn: &mut quiche::Connection,
        socket: &mut mio::net::UdpSocket,
        poll: &mut mio::Poll,
        events: &mut mio::Events,
    ) -> anyhow::Result<()> {
        let mut buf = [0; config::MAX_DATAGRAM_SIZE];
        let mut out = [0; config::MAX_DATAGRAM_SIZE];

        while !conn.is_established() {
            loop {
                match conn.send(&mut out) {
                    Ok((write, send_info)) => match socket.send_to(&out[..write], send_info.to) {
                        Ok(_) => {}
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(e) => return Err(e.into()),
                    },
                    Err(quiche::Error::Done) => break,
                    Err(e) => return Err(e.into()),
                }
            }

            poll.poll(events, conn.timeout())?;

            loop {
                match socket.recv_from(&mut buf) {
                    Ok((len, from)) => {
                        let local = socket.local_addr()?;
                        let recv_info = quiche::RecvInfo { from, to: local };
                        conn.recv(&mut buf[..len], recv_info)?;
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(e) => return Err(e.into()),
                }
            }

            if events.is_empty() {
                conn.on_timeout();
            }

            if conn.is_closed() {
                return Err(anyhow::anyhow!("handshake failed"));
            }
        }

        Ok(())
    }

    pub fn poll_io(&mut self) -> anyhow::Result<()> {
        let local = self.socket.local_addr()?;
        let mut buf = [0; config::MAX_DATAGRAM_SIZE];
        let mut out = [0; config::MAX_DATAGRAM_SIZE];

        // non-blocking poll
        self.poll
            .poll(&mut self.events, Some(std::time::Duration::from_millis(0)))?;

        loop {
            let (len, from) = match self.socket.recv_from(&mut buf) {
                Ok(v) => v,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e.into()),
            };

            let recv_info = quiche::RecvInfo { to: local, from };
            self.conn_quic.recv(&mut buf[..len], recv_info)?;
        }

        if self.events.is_empty() {
            self.conn_quic.on_timeout();
        }

        loop {
            match self.conn_quic.send(&mut out) {
                Ok((write, send_info)) => match self.socket.send_to(&out[..write], send_info.to) {
                    Ok(_) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(e) => return Err(e.into()),
                },
                Err(quiche::Error::Done) => break,
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }

    fn ensure_h3(&mut self) -> anyhow::Result<()> {
        if self.conn_h3.is_none() {
            let h3_config = quiche::h3::Config::new()?;
            self.conn_h3 = Some(quiche::h3::Connection::with_transport(
                &mut self.conn_quic,
                &h3_config,
            )?)
        }
        Ok(())
    }

    pub fn send_request(&mut self, req: &http::Request) -> Result<u64, ClientError> {
        self.ensure_h3().map_err(ClientError::Other)?;

        // Check if the peer allows new streams
        if self.conn_quic.peer_streams_left_bidi() == 0 {
            return Err(ClientError::InFlightFull);
        }

        let h3 = self.conn_h3.as_mut().unwrap();

        let stream_id = match h3.send_request(&mut self.conn_quic, &req.to_quiche(), true) {
            Ok(id) => id,

            // Flow-control prevents sending right now
            Err(quiche::h3::Error::StreamBlocked) => return Err(ClientError::WouldBlock),

            Err(e) => return Err(ClientError::Other(e.into())),
        };

        if self.in_flight.insert(stream_id, InFlight::new()).is_some() {
            return Err(ClientError::Other(anyhow::anyhow!(
                "stream_id {stream_id} already existed"
            )));
        }

        Ok(stream_id)
    }

    pub fn poll_responses(&mut self) -> anyhow::Result<Vec<http::Response>> {
        let Some(h3) = self.conn_h3.as_mut() else {
            return Ok(Vec::new());
        };

        let mut completed: Vec<http::Response> = Vec::new();

        loop {
            match h3.poll(&mut self.conn_quic) {
                Ok((id, quiche::h3::Event::Headers { list, .. })) => {
                    let state = self.in_flight.get_mut(&id).expect("unknown stream id");

                    for h in list {
                        let name = String::from_utf8_lossy(h.name()).to_string();
                        let value = String::from_utf8_lossy(h.value()).to_string();

                        if name == ":status" {
                            state.status = Some(value.parse()?);
                        } else {
                            state.headers.insert(name, value);
                        }
                    }
                }

                Ok((id, quiche::h3::Event::Data)) => {
                    let state = self.in_flight.get_mut(&id).expect("unknown stream id");

                    let mut buf = [0; config::MAX_DATAGRAM_SIZE];

                    while let Ok(read) = h3.recv_body(&mut self.conn_quic, id, &mut buf) {
                        state.body.extend_from_slice(&buf[..read]);
                    }
                }

                Ok((id, quiche::h3::Event::Finished)) => {
                    let state = self.in_flight.remove(&id).expect("unknown stream id");

                    let status = state
                        .status
                        .ok_or_else(|| anyhow::anyhow!("missing :status"))?;

                    completed.push(http::Response::new(status, state.headers, state.body));
                }

                Err(quiche::h3::Error::Done) => break,
                Err(e) => return Err(e.into()),
                _ => {}
            }
        }
        Ok(completed)
    }

    pub fn has_in_flight(&self) -> bool {
        !self.in_flight.is_empty()
    }
}

fn hex_dump(buf: &[u8]) -> String {
    let vec: Vec<String> = buf.iter().map(|b| format!("{b:02x}")).collect();

    vec.join("")
}

// Struct which stores sent request, but which response haven't been received yet
struct InFlight {
    status: Option<u16>,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

impl InFlight {
    pub fn new() -> Self {
        Self {
            status: None,
            headers: HashMap::new(),
            body: Vec::new(),
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum ClientError {
    #[error("in-flight queue is full")]
    InFlightFull,
    #[error("stream error")]
    WouldBlock,

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}
