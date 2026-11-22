# DNS-over-TCP endpoint

`boreas-dns::tcp::TcpDnsServer` uses smoltcp 0.14.0's TCP sockets. It does not
create or bind an OS socket. The embedding application supplies a smoltcp
`Interface`, `Device`, and `SocketSet`, binds the listening sockets to an
explicit DNS VIP on port 53, polls the interface, and calls `process` after
polls. TCP handshake, sequence numbers, retransmission, ACKs, flow control,
reset and half-close are handled by the TCP stack, not by DNS packet code.

## Resource policy

`TcpDnsConfig` fixes the socket count, receive/transmit byte capacity per
connection, DNS frame maximum (at most 4096 bytes), complete frames per `process`
call, an idle timeout, and an absolute active-connection age limit. The socket pool is a fixed-size set of real TCP
sockets. There is no unbounded accept backlog. Each connection's parser and
pending response are bounded by these values. A length prefix of zero, a length
above the configured frame maximum, malformed DNS, resolver refusal, or a
partial frame at receive-half close causes fail-closed connection abort. Frames
are two-byte network-order lengths followed by one DNS message. Arbitrary TCP
segmentation, coalescing, and multiple framed messages are handled by stream
reassembly and a bounded parser state.

## Identity boundary

The embedding Overlay layer must supply `TcpSourceAuthorizer` backed by a live
authenticated-peer binding. An IP address learned from a TCP header alone is not
proof of peer identity. The DNS authority's `SourceAuthorization` allowlist is
also checked before synthesizing each response. Authorization must be rechecked
while a connection is active; revoked peers are aborted.

## Limitations

This is a user-space TCP endpoint, not a TCP socket binding to the host stack.
The caller remains responsible for scheduling timely bounded interface polls,
route/VIP setup in the overlay, propagating peer revocation, and global process
resource budgeting. DNS negative answers still omit SOA records, and the DNS
wire implementation accepts one question per message. No recursion is offered.

The Linux daemon's opt-in private DNS profile integrates this endpoint on one
authenticated Core–Edge circuit. See
[deployment](../../../../docs/engineering/dns-daemon-deployment.md) for the
signed binding, route, resource limits, and netns acceptance case.

## Verification

`tests/tcp.rs` builds client and server `smoltcp::Interface` instances over a
paired virtual `Device` link and exercises the real TCP handshake and streams.
It must be run by GitHub Actions; local cargo/test execution is intentionally
omitted in this work session.
