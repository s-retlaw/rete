//! Minimal DHCP server for WiFi AP mode.
//!
//! Handles DISCOVER→OFFER and REQUEST→ACK. Assigns IPs from 192.168.4.2-20.
//! No lease tracking (always offers the same IP based on client MAC hash).

use embassy_net::udp::{PacketMetadata, UdpSocket};

const SERVER_IP: [u8; 4] = [192, 168, 4, 1];
const SUBNET: [u8; 4] = [255, 255, 255, 0];
const POOL_START: u8 = 2;
const POOL_END: u8 = 20;

// DHCP message types
const DHCP_DISCOVER: u8 = 1;
const DHCP_OFFER: u8 = 2;
const DHCP_REQUEST: u8 = 3;
const DHCP_ACK: u8 = 5;

/// Run a minimal DHCP server on the given stack.
pub async fn run(stack: embassy_net::Stack<'static>) -> ! {
    // Wait for link
    loop {
        if stack.is_link_up() { break; }
        embassy_time::Timer::after(embassy_time::Duration::from_millis(500)).await;
    }
    esp_println::println!("[dhcp] DHCP server starting on UDP/67");
    let mut rx_meta = [PacketMetadata::EMPTY; 4];
    let mut rx_buf = [0u8; 600];
    let mut tx_meta = [PacketMetadata::EMPTY; 4];
    let mut tx_buf = [0u8; 600];

    let mut socket = UdpSocket::new(stack, &mut rx_meta, &mut rx_buf, &mut tx_meta, &mut tx_buf);
    socket.bind(67).unwrap();

    let mut pkt = [0u8; 576];

    loop {
        let (n, _ep) = match socket.recv_from(&mut pkt).await {
            Ok(r) => r,
            Err(_) => continue,
        };
        if n < 240 {
            continue;
        }

        // DHCP is BOOTP: op=1 is request from client
        if pkt[0] != 1 {
            continue;
        }

        // Extract client MAC (offset 28, 6 bytes)
        let mac = &pkt[28..34];

        // Find DHCP message type in options (starting at offset 240)
        let msg_type = find_option(&pkt[240..n], 53).and_then(|v| v.first().copied());
        let msg_type = match msg_type {
            Some(t) => t,
            None => continue,
        };

        // Assign IP based on MAC hash
        let offered_ip = POOL_START + (mac_hash(mac) % (POOL_END - POOL_START + 1));

        let reply_type = match msg_type {
            DHCP_DISCOVER => {
                esp_println::println!("[dhcp] DISCOVER from {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} -> offer 192.168.4.{}", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], offered_ip);
                DHCP_OFFER
            }
            DHCP_REQUEST => {
                esp_println::println!("[dhcp] REQUEST -> ACK 192.168.4.{}", offered_ip);
                DHCP_ACK
            }
            _ => continue,
        };

        // Build reply
        let mut reply = [0u8; 576];
        reply[0] = 2; // op: reply
        reply[1] = pkt[1]; // htype
        reply[2] = pkt[2]; // hlen
        // xid (transaction ID) — copy from request
        reply[4..8].copy_from_slice(&pkt[4..8]);
        // yiaddr (your IP address)
        reply[16] = 192;
        reply[17] = 168;
        reply[18] = 4;
        reply[19] = offered_ip;
        // siaddr (server IP)
        reply[20..24].copy_from_slice(&SERVER_IP);
        // chaddr (client MAC)
        reply[28..44].copy_from_slice(&pkt[28..44]);
        // Magic cookie
        reply[236] = 99;
        reply[237] = 130;
        reply[238] = 83;
        reply[239] = 99;

        // DHCP options
        let mut pos = 240;
        // Option 53: DHCP Message Type
        reply[pos] = 53;
        reply[pos + 1] = 1;
        reply[pos + 2] = reply_type;
        pos += 3;
        // Option 54: Server Identifier
        reply[pos] = 54;
        reply[pos + 1] = 4;
        reply[pos + 2..pos + 6].copy_from_slice(&SERVER_IP);
        pos += 6;
        // Option 51: Lease Time (1 hour)
        reply[pos] = 51;
        reply[pos + 1] = 4;
        reply[pos + 2..pos + 6].copy_from_slice(&3600u32.to_be_bytes());
        pos += 6;
        // Option 1: Subnet Mask
        reply[pos] = 1;
        reply[pos + 1] = 4;
        reply[pos + 2..pos + 6].copy_from_slice(&SUBNET);
        pos += 6;
        // Option 3: Router
        reply[pos] = 3;
        reply[pos + 1] = 4;
        reply[pos + 2..pos + 6].copy_from_slice(&SERVER_IP);
        pos += 6;
        // Option 6: DNS
        reply[pos] = 6;
        reply[pos + 1] = 4;
        reply[pos + 2..pos + 6].copy_from_slice(&SERVER_IP);
        pos += 6;
        // End
        reply[pos] = 255;
        pos += 1;

        // Send to broadcast
        let dest = (
            embassy_net::IpAddress::v4(255, 255, 255, 255),
            68u16,
        );
        let _ = socket.send_to(&reply[..pos], dest).await;
    }
}

/// Find a DHCP option by tag in the options section.
fn find_option<'a>(options: &'a [u8], tag: u8) -> Option<&'a [u8]> {
    let mut i = 0;
    while i < options.len() {
        let t = options[i];
        if t == 255 {
            break; // end
        }
        if t == 0 {
            i += 1; // pad
            continue;
        }
        if i + 1 >= options.len() {
            break;
        }
        let len = options[i + 1] as usize;
        if t == tag {
            return options.get(i + 2..i + 2 + len);
        }
        i += 2 + len;
    }
    None
}

/// Simple hash of MAC address to pick an IP.
fn mac_hash(mac: &[u8]) -> u8 {
    let mut h: u8 = 0;
    for &b in mac {
        h = h.wrapping_add(b).wrapping_mul(31);
    }
    h
}
