use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering::Relaxed;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use rand::random;
use socket2::{Domain, Protocol, Type};
use tokio::time::timeout;

use crate::Error;
use crate::packet::{EchoReply, EchoRequest, ICMP_HEADER_SIZE, IcmpV4, IcmpV6};
use crate::packet::{IpV4Packet, IpV4Protocol};
use crate::socket::Socket;

const TOKEN_SIZE: usize = 24;
const ECHO_REQUEST_BUFFER_SIZE: usize = ICMP_HEADER_SIZE + TOKEN_SIZE;
type Token = [u8; TOKEN_SIZE];

#[repr(transparent)]
struct PingState {
    inner: Mutex<HashMap<Token, kanal::OneshotAsyncSender<()>>>,
}

impl PingState {
    fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    fn insert(&self, key: Token, value: kanal::OneshotAsyncSender<()>) {
        self.inner.lock().insert(key, value);
    }

    fn remove(&self, key: &[u8]) -> Option<kanal::OneshotAsyncSender<()>> {
        self.inner.lock().remove(key)
    }
}

#[derive(Debug)]
pub enum PingFutureKind {
    Normal(Duration),
    NoResponse,
    PacketSendError,
    PacketEncodeError,
    InvalidProtocol,
}

/// ICMP packets sender and receiver.
#[derive(Clone)]
pub struct Pinger {
    inner: Arc<PingInner>,
}

struct PingInner {
    sockets: Sockets,
    alive: Arc<AtomicBool>,
    state: PingState,
}

impl Drop for PingInner {
    fn drop(&mut self) {
        self.alive.store(false, Relaxed)
    }
}

enum Sockets {
    V4(Socket),
    V6(Socket),
    Both { v4: Socket, v6: Socket },
}

impl Sockets {
    fn new() -> io::Result<Self> {
        let mb_v4socket = Socket::new(Domain::IPV4, Type::RAW, Protocol::ICMPV4);
        let mb_v6socket = Socket::new(Domain::IPV6, Type::RAW, Protocol::ICMPV6);
        match (mb_v4socket, mb_v6socket) {
            (Ok(v4_socket), Ok(v6_socket)) => Ok(Sockets::Both {
                v4: v4_socket,
                v6: v6_socket,
            }),
            (Ok(v4_socket), Err(_)) => Ok(Sockets::V4(v4_socket)),
            (Err(_), Ok(v6_socket)) => Ok(Sockets::V6(v6_socket)),
            (Err(err), Err(_)) => Err(err),
        }
    }

    fn v4(&self) -> Option<&Socket> {
        match *self {
            Sockets::V4(ref socket) => Some(socket),
            Sockets::Both { ref v4, .. } => Some(v4),
            Sockets::V6(_) => None,
        }
    }

    fn v6(&self) -> Option<&Socket> {
        match *self {
            Sockets::V4(_) => None,
            Sockets::Both { ref v6, .. } => Some(v6),
            Sockets::V6(ref socket) => Some(socket),
        }
    }
}

impl Pinger {
    /// Create new `Pinger` instance, will fail if unable to create both IPv4 and IPv6 sockets.
    pub async fn new() -> Result<Self, Error> {
        let sockets = Sockets::new()?;

        let state = PingState::new();

        let inner = Arc::new(PingInner {
            sockets,
            alive: Arc::new(AtomicBool::new(true)),
            state,
        });

        let state = inner.clone();
        if state.sockets.v4().is_some() {
            tokio::spawn(async move {
                let mut buffer = [0; 2048];
                let socket = state.sockets.v4().unwrap();
                while state.alive.load(Relaxed) {
                    let x = socket.recv(&mut buffer).await;
                    if let Ok(bytes) = x {
                        if let Some(payload) = IcmpV4::reply_payload(&buffer[..bytes]) {
                            if let Some(sender) = state.state.remove(payload) {
                                let _ = sender.send(()).await;
                            }
                        }
                    }
                }
            });
        }
        let state = inner.clone();
        if state.sockets.v6().is_some() {
            tokio::spawn(async move {
                let mut buffer = [0; 2048];
                let socket = state.sockets.v6().unwrap();
                while state.alive.load(Relaxed) {
                    let x = socket.recv(&mut buffer).await;
                    if let Ok(bytes) = x {
                        if let Some(payload) = IcmpV6::reply_payload(&buffer[..bytes]) {
                            if let Some(sender) = state.state.remove(payload) {
                                let _ = sender.send(()).await;
                            }
                        }
                    }
                }
            });
        }

        Ok(Self {
            inner,
        })
    }

    /// Send ICMP request and wait for response.
    pub async fn ping(
        &self,
        hostname: IpAddr,
        ident: u16,
        seq_cnt: u16,
        timeout_duration: Duration,
    ) -> PingFutureKind {
        let (sender, receiver) = kanal::oneshot_async();

        let token = random();
        self.inner.state.insert(token, sender);

        let dest = SocketAddr::new(hostname, 0);
        let mut buffer = [0; ECHO_REQUEST_BUFFER_SIZE];

        let request = EchoRequest {
            ident,
            seq_cnt,
            payload: &token,
        };

        let (encode_result, mb_socket) = {
            if dest.is_ipv4() {
                (
                    request.encode::<IcmpV4>(&mut buffer[..]),
                    self.inner.sockets.v4().cloned(),
                )
            } else {
                (
                    request.encode::<IcmpV6>(&mut buffer[..]),
                    self.inner.sockets.v6().cloned(),
                )
            }
        };

        let socket = match mb_socket {
            Some(socket) => socket,
            None => {
                return PingFutureKind::InvalidProtocol
            }
        };

        if encode_result.is_err() {
            return PingFutureKind::PacketEncodeError;
        }

        let send_future = socket.send_to(buffer, &dest).await;
        let start_time = Instant::now();
        if send_future.is_err() {
            return PingFutureKind::PacketSendError;
        }
        let res = timeout(timeout_duration, receiver.recv()).await;
        let elapsed = start_time.elapsed();
        if res.is_err() {
            return PingFutureKind::NoResponse;
        }
        let res = res.unwrap();
        if res.is_err() {
            return PingFutureKind::NoResponse;
        }
        PingFutureKind::Normal(elapsed)
    }
}

trait ParseReply {
    fn reply_payload(data: &[u8]) -> Option<&[u8]>;
}

impl ParseReply for IcmpV4 {
    fn reply_payload(data: &[u8]) -> Option<&[u8]> {
        if let Ok(ipv4_packet) = IpV4Packet::decode(data) {
            if ipv4_packet.protocol != IpV4Protocol::Icmp {
                return None;
            }

            if let Ok(reply) = EchoReply::decode::<IcmpV4>(ipv4_packet.data) {
                return Some(reply.payload);
            }
        }
        None
    }
}

impl ParseReply for IcmpV6 {
    fn reply_payload(data: &[u8]) -> Option<&[u8]> {
        if let Ok(reply) = EchoReply::decode::<IcmpV6>(data) {
            return Some(reply.payload);
        }
        None
    }
}
