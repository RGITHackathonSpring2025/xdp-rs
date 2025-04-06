#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{HashMap, PerCpuArray},
    programs::XdpContext,
};
use aya_log_ebpf::info;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr, Ipv6Hdr},
    tcp::TcpHdr,
};

// Connection states
const CONN_NEW: u32 = 0;
const CONN_ESTABLISHED: u32 = 1;
const CONN_HTTP: u32 = 2;
const CONN_HTTPS: u32 = 3;

// Map to track TCP connections and their states
#[map(name = "TCP_CONNECTIONS")]
static mut TCP_CONNECTIONS: HashMap<u32, u32> = HashMap::with_max_entries(10000, 0);

// Map to store packet fragments for reassembly
#[map(name = "PACKET_FRAGMENTS")]
static mut PACKET_FRAGMENTS: HashMap<u32, [u8; 1500]> = HashMap::with_max_entries(1000, 0);

// Statistics map for packet analysis
#[map(name = "PROTOCOL_STATS")]
static mut PROTOCOL_STATS: PerCpuArray<u32> = PerCpuArray::with_max_entries(256, 0);

// HTTP signatures for all versions
const HTTP_METHODS: [&[u8]; 7] = [
    b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"PATCH ", b"OPTIONS ",
];

const HTTP_VERSIONS: [&[u8]; 4] = [
    b"HTTP/1.0", b"HTTP/1.1", b"HTTP/2.0", b"HTTP/3.0",
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

// QUIC signatures to block
const QUIC_SIGNATURES: [&[u8]; 2] = [
    b"QUIC", b"Q043",
];

#[xdp]
pub fn traffic_monitor(ctx: XdpContext) -> u32 {
    match try_traffic_monitor(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, u32> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = core::mem::size_of::<T>();

    if start + offset + len > end {
        return Err(xdp_action::XDP_ABORTED);
    }

    Ok((start + offset) as *const T)
}

#[inline(always)]
fn is_quic_traffic(ctx: &XdpContext, offset: usize) -> bool {
    let start = ctx.data();
    let end = ctx.data_end();
    
    if start + offset + 4 > end {
        return false;
    }
    
    let payload_start = start + offset;
    
    for sig in QUIC_SIGNATURES.iter() {
        if payload_start + sig.len() <= end {
            let mut is_match = true;
            for i in 0..sig.len() {
                if unsafe { *(payload_start as *const u8).add(i) } != sig[i] {
                    is_match = false;
                    break;
                }
            }
            if is_match {
                info!(ctx, "Blocking QUIC traffic");
                return true;
            }
        }
    }
    
    false
}

#[inline(always)]
fn analyze_packet_content(ctx: &XdpContext, offset: usize) -> Option<u32> {
    let start = ctx.data();
    let end = ctx.data_end();
    
    if start + offset + 10 > end {
        return None;
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
                info!(ctx, "Detected HTTP method in packet");
                return Some(CONN_HTTP);
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
                info!(ctx, "Detected HTTP version in packet");
                return Some(CONN_HTTP);
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
                info!(ctx, "Detected HTTP header in packet");
                return Some(CONN_HTTP);
            }
        }
    }
    
    // Check for TLS handshake signatures
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
                info!(ctx, "Detected TLS handshake in packet");
                return Some(CONN_HTTPS);
            }
        }
    }
    
    None
}

fn try_traffic_monitor(ctx: XdpContext) -> Result<u32, u32> {
    // Parse Ethernet header
    let eth = ptr_at::<EthHdr>(&ctx, 0)?;
    let eth_proto = unsafe { (*eth).ether_type };
    let ip_proto;
    let mut offset = EthHdr::LEN;

    // Handle different protocols
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
        _ => return Ok(xdp_action::XDP_PASS),
    }

    // Update protocol statistics
    unsafe {
        let stats_ptr = core::ptr::addr_of_mut!(PROTOCOL_STATS);
        if let Some(stats) = (*stats_ptr).get_ptr_mut(0) {
            *stats += 1;
        }
    }

    // Handle TCP traffic
    if ip_proto == IpProto::Tcp {
        let tcp = ptr_at::<TcpHdr>(&ctx, offset)?;
        let dst_port = unsafe { (*tcp).dest };
        let src_port = unsafe { (*tcp).source };
        
        // Calculate TCP header length
        let tcp_header_len = (unsafe { (*tcp).doff() } as usize) * 4;
        offset += tcp_header_len;

        // Get TCP flags
        let flags = unsafe { 
            (*tcp).fin() | 
            ((*tcp).syn() << 1) | 
            ((*tcp).rst() << 2) | 
            ((*tcp).psh() << 3) | 
            ((*tcp).ack() << 4) | 
            ((*tcp).urg() << 5) 
        };
        
        // Generate connection keys for both directions
        let fwd_key = ((src_port as u32) << 16) | (dst_port as u32);
        let rev_key = ((dst_port as u32) << 16) | (src_port as u32);
        
        unsafe {
            let conn_ptr = core::ptr::addr_of_mut!(TCP_CONNECTIONS);
            
            // Check existing connections first
            if let Some(state) = (*conn_ptr).get(&fwd_key).or_else(|| (*conn_ptr).get(&rev_key)) {
                match *state {
                    CONN_NEW => {
                        // For new connections, allow SYN-ACK and analyze content
                        if flags == 18 { // SYN-ACK
                            let value = CONN_ESTABLISHED;
                            (*conn_ptr).insert(&fwd_key, &value, 0).map_err(|_| xdp_action::XDP_DROP)?;
                            return Ok(xdp_action::XDP_PASS);
                        }
                        // Allow all control packets for new connections
                        if flags & 0x3F != 0 { // Any control flags set
                            return Ok(xdp_action::XDP_PASS);
                        }
                        
                        // For data packets in new connections, analyze content
                        if let Some(conn_type) = analyze_packet_content(&ctx, offset) {
                            (*conn_ptr).insert(&fwd_key, &conn_type, 0).map_err(|_| xdp_action::XDP_DROP)?;
                            return Ok(xdp_action::XDP_PASS);
                        }
                    },
                    CONN_ESTABLISHED => {
                        // For established connections, analyze content
                        if let Some(conn_type) = analyze_packet_content(&ctx, offset) {
                            (*conn_ptr).insert(&fwd_key, &conn_type, 0).map_err(|_| xdp_action::XDP_DROP)?;
                            return Ok(xdp_action::XDP_PASS);
                        }
                        
                        // Allow control packets for established connections
                        if flags & 0x3F != 0 { // Any control flags set
                            return Ok(xdp_action::XDP_PASS);
                        }
                        
                        // Block data packets for established connections that aren't HTTP/HTTPS
                        info!(&ctx, "Blocking non-HTTP/HTTPS traffic");
                        return Ok(xdp_action::XDP_DROP);
                    },
                    CONN_HTTP | CONN_HTTPS => {
                        // Allow all traffic for HTTP/HTTPS connections
                        return Ok(xdp_action::XDP_PASS);
                    },
                    _ => {}
                }
            } else if flags == 2 { // New SYN packet
                // Create new connection entry
                let value = CONN_NEW;
                (*conn_ptr).insert(&fwd_key, &value, 0).map_err(|_| xdp_action::XDP_DROP)?;
                return Ok(xdp_action::XDP_PASS);
            }
            
            // Block QUIC traffic
            if is_quic_traffic(&ctx, offset) {
                info!(&ctx, "Blocking QUIC traffic");
                return Ok(xdp_action::XDP_DROP);
            }
            
            // For untracked connections, analyze content
            if let Some(conn_type) = analyze_packet_content(&ctx, offset) {
                (*conn_ptr).insert(&fwd_key, &conn_type, 0).map_err(|_| xdp_action::XDP_DROP)?;
                return Ok(xdp_action::XDP_PASS);
            }
            
            // Block all TCP traffic by default
            info!(&ctx, "Blocking non-HTTP/HTTPS traffic");
            return Ok(xdp_action::XDP_DROP);
        }
    }
    
    // Allow non-TCP traffic
    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
