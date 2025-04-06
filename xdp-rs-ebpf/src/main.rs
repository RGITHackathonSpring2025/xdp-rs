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
    
    if start + offset + 10 > end {
        return false;
    }
    
    let payload_start = start + offset;
    
    // Check for HTTP methods
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
    
    // Check for HTTP versions
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
    
    // Check for HTTP headers
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
    
    // Check for TLS handshake signatures (HTTPS)
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

    match eth_proto {
        EtherType::Ipv4 => {
            let ipv4 = ptr_at::<Ipv4Hdr>(&ctx, offset)?;
            ip_proto = unsafe { (*ipv4).proto };
            offset += Ipv4Hdr::LEN;
        }
        EtherType::Ipv6 => {
            let ipv6 = ptr_at::<Ipv6Hdr>(&ctx, offset)?;
            ip_proto = unsafe { (*ipv6).next_hdr };
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
                    // Calculate TCP header length to find payload
                    let tcp_header_len = (unsafe { (*tcphdr).doff() } as usize) * 4;
                    offset += tcp_header_len;
                    
                    // Check if this is HTTP/HTTPS traffic by inspecting packet contents
                    if is_http_traffic(&ctx, offset) {
                        info!(&ctx, "HTTP/HTTPS traffic allowed on port {}", dst_port);
                        return Ok(xdp_action::XDP_PASS);
                    }
                    
                    // Block non-HTTP traffic
                    info!(&ctx, "Non-HTTP/HTTPS traffic blocked on port {}", dst_port);
                    return Ok(xdp_action::XDP_DROP);
                },
                // No rule found, use default policy
                None => {
                    return Ok(get_default_action());
                },
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
                // No rule found, use default policy
                None => {
                    return Ok(get_default_action());
                },
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
