use std::net::UdpSocket;
use rand;

fn request_ack_tlv() -> [u8; 8] {
    let first: [u8; 4] = [2, 6, 0, 0];
    let mut opaque: [u8; 2] = [0u8;2];
    rand::fill(&mut opaque);
    let last: [u8; 2] = [0, 200];

    // Concatenate first, opaque, and last into tlv
    let mut tlv = [0u8; 8];
    tlv[0..4].copy_from_slice(&first);
    tlv[4..6].copy_from_slice(&opaque);
    tlv[6..8].copy_from_slice(&last);

    tlv
}

fn main() {
    // Create UDP socket on Babel port
    let socket = UdpSocket::bind("127.0.0.1:6696").expect("Couldn't bind to socket");

    // generate a request ack tlv
    let tlv = request_ack_tlv();

    // Take length of tlv (or other resultant body array) and split it into the 2 u8 required in header
    let body_length: u16 = tlv.len().try_into().unwrap();
    let high_bl : u8 = (body_length >> 8) as u8;
    let low_bl : u8 = (body_length & 0xff) as u8;
    
    // Create the header for the message
    let header=[42, 2, high_bl, low_bl];

    // Concatenate header and tlv
    let mut combined = Vec::with_capacity(header.len() + tlv.len());
    combined.extend_from_slice(&header);
    combined.extend_from_slice(&tlv);

    // Send the combined babel packet to the UDP socket, to babel unicast
    // (prolly doesn't make sense given we're bound to loopback)
    socket.send_to(&combined, "224.0.0.111:6696").expect("Couldn't send packet: ");
}
