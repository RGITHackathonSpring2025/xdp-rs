#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::HashMap,
    programs::XdpContext,
};

use aya_log_ebpf::info;

use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{Ipv4Hdr, IpProto, Ipv6Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

// Rule types: 0 = BLOCK, 1 = ALLOW, 2 = ALLOW_HTTP_ONLY
#[map(name = "TCP_RULES")]
static mut TCP_RULES: HashMap<u16, u8> = HashMap::with_max_entries(1024, 0);

#[map(name = "UDP_RULES")]
static mut UDP_RULES: HashMap<u16, u8> = HashMap::with_max_entries(1024, 0);

// Default policy: 0 = DROP, 1 = ACCEPT
#[map(name = "DEFAULT_POLICY")]
static mut DEFAULT_POLICY: HashMap<u32, u8> = HashMap::with_max_entries(1, 0);

// Connection tracking for HTTP/HTTPS connections
// Key: (src_ip, dst_ip, src_port, dst_port)
// Value: 1 = HTTP/HTTPS connection
#[repr(C)]
#[derive(Clone, Copy)]
struct ConnKey {
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
}

#[map(name = "HTTP_CONN_TRACK")]
static mut HTTP_CONN_TRACK: HashMap<ConnKey, u8> = HashMap::with_max_entries(65536, 0);

const HTTP_METHODS: [&[u8]; 9] = [
    b"GET ",
    b"POST ",
    b"HEAD ",
    b"PUT ",
    b"DELETE ",
    b"PATCH ",
    b"OPTIONS ",
    b"TRACE ",
    b"CONNECT ",
];

const HTTP_VERSIONS: [&[u8]; 4] = [
    b"HTTP/1.0",
    b"HTTP/1.1",
    b"HTTP/2.0",
    b"HTTP/3.0",
];

const HTTP_HEADERS: [&[u8]; 8] = [
    b"Host: ", b"User-Agent: ", b"Accept: ", b"Content-Type: ", 
    b"Connection: ", b"Cookie: ", b"Authorization: ", b"Content-Length: ",
];

// TLS handshake signatures for all versions
const TLS_HANDSHAKE: [&[u8]; 5] = [
    b"\x16\x03\x00", // SSL 3.0
    b"\x16\x03\x01", // TLS 1.0
    b"\x16\x03\x02", // TLS 1.1
    b"\x16\x03\x03", // TLS 1.2
    b"\x16\x03\x04", // TLS 1.3
];

const TCP_FLAG_FIN: u8 = 0x01;
const TCP_FLAG_SYN: u8 = 0x02;
const TCP_FLAG_RST: u8 = 0x04;
const TCP_FLAG_PSH: u8 = 0x08;
const TCP_FLAG_ACK: u8 = 0x10;
const TCP_FLAG_URG: u8 = 0x20;

#[xdp]
pub fn xdp_rs(ctx: XdpContext) -> u32 {
    match try_xdp_firewall(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline(always)]  
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

#[inline(always)]
fn is_http_traffic(ctx: &XdpContext, offset: usize) -> bool {
    let start = ctx.data();
    let end = ctx.data_end();
    
    // Ensure we have at least some data to check
    if start + offset + 4 > end {
        return false;
    }
    
    let payload_start = start + offset;
    
    // First check for TLS handshake (HTTPS) as it's a simple pattern
    for handshake in TLS_HANDSHAKE.iter() {
        if payload_start + handshake.len() <= end {
            let mut is_match = true;
            for i in 0..handshake.len() {
                if unsafe { *(payload_start as *const u8).add(i) } != handshake[i] {
                    is_match = false;
                    break;
                }
            }
            if is_match {
                return true;
            }
        }
    }
    
    // Next check for HTTP methods which are more common in initial requests
    for method in HTTP_METHODS.iter() {
        if payload_start + method.len() <= end {
            let mut is_match = true;
            for i in 0..method.len() {
                if unsafe { *(payload_start as *const u8).add(i) } != method[i] {
                    is_match = false;
                    break;
                }
            }
            if is_match {
                return true;
            }
        }
    }
    
    // Then check for HTTP versions which might appear in responses
    for version in HTTP_VERSIONS.iter() {
        if payload_start + version.len() <= end {
            let mut is_match = true;
            for i in 0..version.len() {
                if unsafe { *(payload_start as *const u8).add(i) } != version[i] {
                    is_match = false;
                    break;
                }
            }
            if is_match {
                return true;
            }
        }
    }
    
    // Finally check for common HTTP headers
    for header in HTTP_HEADERS.iter() {
        if payload_start + header.len() <= end {
            let mut is_match = true;
            for i in 0..header.len() {
                if unsafe { *(payload_start as *const u8).add(i) } != header[i] {
                    is_match = false;
                    break;
                }
            }
            if is_match {
                return true;
            }
        }
    }
    
    false
}

fn get_default_action() -> u32 {
    // Get default policy, or DROP if not set
    match unsafe { DEFAULT_POLICY.get(&0) } {
        Some(&1) => xdp_action::XDP_PASS,
        _ => xdp_action::XDP_DROP,
    }
}

fn try_xdp_firewall(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?;  
    let eth_proto = unsafe { (*ethhdr).ether_type };
    let ip_proto;
    let mut offset = EthHdr::LEN;
    let mut src_ip = 0;
    let mut dst_ip = 0;

    match eth_proto {
        EtherType::Ipv4 => {
            let ipv4 = ptr_at::<Ipv4Hdr>(&ctx, offset)?;
            ip_proto = unsafe { (*ipv4).proto };
            src_ip = u32::from_be(unsafe { (*ipv4).src_addr });
            dst_ip = u32::from_be(unsafe { (*ipv4).dst_addr });
            offset += Ipv4Hdr::LEN;
        }
        EtherType::Ipv6 => {
            // For IPv6, we'll use a hash of the address as the IP
            // This is a simplification for demonstration purposes
            let ipv6 = ptr_at::<Ipv6Hdr>(&ctx, offset)?;
            ip_proto = unsafe { (*ipv6).next_hdr };
            // Using first 4 bytes of IPv6 addr as simple hash
            src_ip = unsafe { *((*ipv6).src_addr.in6_u.u6_addr32.get_unchecked(0)) };
            dst_ip = unsafe { *((*ipv6).dst_addr.in6_u.u6_addr32.get_unchecked(0)) };
            offset += Ipv6Hdr::LEN;
        }
        _ => {
            // Non-IP packets use default policy
            return Ok(get_default_action());
        }
    }

    match ip_proto {
        IpProto::Tcp => {
            let tcphdr: *const TcpHdr = ptr_at(&ctx, offset)?;
            let src_port = u16::from_be(unsafe { (*tcphdr).source });
            let dst_port = u16::from_be(unsafe { (*tcphdr).dest });
            
            // Check if we have a rule for this port
            match unsafe { TCP_RULES.get(&dst_port) } {
                // BLOCK
                Some(&0) => {
                    info!(&ctx, "TCP port {} blocked by rule", dst_port);
                    return Ok(xdp_action::XDP_DROP);
                },
                // ALLOW
                Some(&1) => {
                    info!(&ctx, "TCP port {} allowed by rule", dst_port);
                    return Ok(xdp_action::XDP_PASS);
                },
                // ALLOW_HTTP_ONLY
                Some(&2) => {
                    // Create connection key for tracking
                    let conn_key = ConnKey {
                        src_ip,
                        dst_ip,
                        src_port,
                        dst_port,
                    };
                    
                    // Check if this connection is already known to be HTTP/HTTPS
                    if let Some(&1) = unsafe { HTTP_CONN_TRACK.get(&conn_key) } {
                        // Already identified as HTTP/HTTPS connection
                        return Ok(xdp_action::XDP_PASS);
                    }
                    
                    let flags_offset = offset + 13;
                    let tcp_flags = match ptr_at::<u8>(&ctx, flags_offset) {
                        Ok(ptr) => unsafe { *ptr },
                        Err(_) => return Err(()),
                    };
                    
                    let is_syn = tcp_flags & TCP_FLAG_SYN != 0;
                    let is_rst = tcp_flags & TCP_FLAG_RST != 0;
                    let is_fin = tcp_flags & TCP_FLAG_FIN != 0;

                    
                    // If connection is being reset or finished, clean up tracking
                    if is_rst || is_fin {
                        unsafe { HTTP_CONN_TRACK.remove(&conn_key) };
                        return Ok(get_default_action());
                    }
                    
                    // Calculate TCP header length to find payload
                    let tcp_header_len = (unsafe { (*tcphdr).doff() } as usize) * 4;
                    offset += tcp_header_len;
                    
                    // Check for payload. If no payload, allow the packet (likely a handshake)
                    let start = ctx.data();
                    let end = ctx.data_end();
                    if start + offset >= end {
                        // No payload, could be a SYN or ACK packet
                        if is_syn {
                            // Allow SYN packets to establish connections
                            return Ok(xdp_action::XDP_PASS);
                        }
                        // For other packets with no payload, use default policy
                        return Ok(get_default_action());
                    }
                    
                    // For packets with payload, check if it's HTTP/HTTPS
                    if is_http_traffic(&ctx, offset) {
                        // Add to connection tracking
                        unsafe { HTTP_CONN_TRACK.insert(&conn_key, &1, 0) };
                        info!(&ctx, "HTTP/HTTPS traffic detected and tracked on port {}", dst_port);
                        return Ok(xdp_action::XDP_PASS);
                    }
                    
                    // Payload exists but not HTTP/HTTPS
                    // For SYN packets, we'll allow them to possibly establish HTTP/HTTPS later
                    if is_syn {
                        return Ok(xdp_action::XDP_PASS);
                    }
                    
                    // Block non-HTTP traffic that isn't part of connection establishment
                    info!(&ctx, "Non-HTTP/HTTPS traffic blocked on port {}", dst_port);
                    return Ok(xdp_action::XDP_DROP);
                },
                // No rule found or invalid rule, use default policy
                _ => {
                    return Ok(get_default_action());
                }
                Some(&(2_u8..=u8::MAX)) => {
                    return Ok(get_default_action());
                }
            }
        }
        IpProto::Udp => {
            let udphdr: *const UdpHdr = ptr_at(&ctx, offset)?;
            let dst_port = u16::from_be(unsafe { (*udphdr).dest });
            
            // Check if we have a rule for this UDP port
            match unsafe { UDP_RULES.get(&dst_port) } {
                // BLOCK
                Some(&0) => {
                    info!(&ctx, "UDP port {} blocked by rule", dst_port);
                    return Ok(xdp_action::XDP_DROP);
                },
                // ALLOW
                Some(&1) => {
                    info!(&ctx, "UDP port {} allowed by rule", dst_port);
                    return Ok(xdp_action::XDP_PASS);
                },
                // No rule found or invalid rule, use default policy
                _ => {
                    return Ok(get_default_action());
                }
                Some(&(2_u8..=u8::MAX)) => {
                    return Ok(get_default_action());
                }
            }
        }
        _ => {
            // Other protocols use default policy
            return Ok(get_default_action());
        }
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
