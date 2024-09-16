// Title: toPDF v0.0.1
extern crate aes;
extern crate base32;
extern crate clap;
extern crate ctrlc;
extern crate hex;
extern crate hkdf;
extern crate hmac;
extern crate libc;
extern crate lopdf;
extern crate nftnl_sys;
extern crate nix;
extern crate pnet;
extern crate printpdf;
extern crate rand;
extern crate sha2;
extern crate time;
extern crate tun;

use aes::cipher::{typenum, Array, BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use aes::*;
use base32::Alphabet;
use clap::{Arg, ArgAction};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use nftnl_sys::*;
use nix::fcntl::{fcntl, FcntlArg, OFlag};
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::Packet;
use printpdf::*;
use rand::Rng;
use sha2::Sha512;
use std::ffi::CStr;
use std::process::{exit, Command};
use std::sync::atomic::{AtomicBool, Ordering};
use time::OffsetDateTime;
use tun::platform::Queue;
use tun::Device;

use std::borrow::{Borrow, BorrowMut};
use std::error::Error;
use std::fs::File;
use std::io::Write;
use std::io::{self, Read};
use std::net::{IpAddr, Ipv4Addr};
use std::panic;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex, Once};
use std::thread;

use libc::{
    bind, close, recv, send, sendto, sockaddr, sockaddr_ll, sockaddr_nl, socket, AF_NETLINK,
    AF_PACKET, NETLINK_NETFILTER, NFNL_SUBSYS_QUEUE, NFQNL_MSG_VERDICT, SOCK_RAW,
};
use std::os::raw::c_void;
use std::os::unix::io::RawFd;

// Set the page size to Letter (210.0 x 297.0 mm)
const MARGIN: f64 = 2.4; // Margin in mm DEFAULT:2.4 for whole page.
const LINE_HEIGHT: f64 = 6.0; // Line height in mm
const INITIAL_PAGE_WIDTH: Mm = Mm(210.0);
const INITIAL_PAGE_HEIGHT: Mm = Mm(80.0); // DEFAULT:297.0
const EMPTY_LINE_WIDTH: f64 = 210.0;
const TOP_PAGE: f64 = 80.0; //DEFAULT:297.0 -12.0
                            //const NLMSG_ACK: u16 = 0; // Acknowledgment message type
                            //const NFQA_MANGLE: u16 = 0x0003; // Mangle queue type
                            //const AF_NETLINK: i32 = 16; // Address family for netlink
                            //const NETLINK_NETFILTER: i32 = 12; // Netlink protocol for netfilter
                            //const NETLINK_RAW: i32 = 0;

static INIT: Once = Once::new();
static INIT2: Once = Once::new();
static INIT3: Once = Once::new();
static INIT4: Once = Once::new();
static INIT5: Once = Once::new();
static INIT6: Once = Once::new();
static INIT7: Once = Once::new();
static INIT8: Once = Once::new();
static mut SECRET: Option<String> = None;
static mut OTP: u64 = 0;
static mut IN_SYNC: bool = false;
static mut SERVER: bool = false;
static mut IFACE: String = String::new();
static mut ROUTED: String = String::new();
static mut CLIENT_IP: String = String::new();
static mut IP: String = String::new();
static mut TUN_NAME: String = String::new();

pub enum Verdict {
    //NFQUEUE Verdicts
    NfAccept = 1,
    NfDrop = 0,
    NfStolen = 2,
    NfQueue = 3,
    NfRepeat = 4,
    NfStop = 5,
}

// Shared state for cleanup
struct SharedState {
    cleanup_sender: Sender<()>,
}

// Common cleanup function
fn cleanup_and_exit() {
    unsafe {
        del_route(ROUTED.borrow(), IFACE.borrow());
    }
    let _ = flush_nftables(); // Flush nftables on shutdown
    exit_program(); // Exit immediately after flushing
}

fn is_elevated() -> bool {
    // Check if the user ID is 0 (root)
    unsafe { libc::getuid() == 0 }
}

fn init_secret(secret: String) {
    unsafe {
        INIT.call_once(|| {
            SECRET = Some(secret);
        });
    }
}

fn init_otp(otp: u64) {
    unsafe {
        INIT2.call_once(|| {
            OTP = otp;
        });
    }
}

fn is_server() -> bool {
    unsafe { SERVER }
}

fn init_server() {
    unsafe {
        INIT3.call_once(|| {
            SERVER = true;
        });
    }
}

fn init_iface(iface: String) {
    unsafe {
        INIT4.call_once(|| {
            IFACE = iface;
        });
    }
}

fn init_routed(routable: String) {
    unsafe {
        INIT5.call_once(|| {
            ROUTED = routable;
        });
    }
}

fn init_client_ip(client_ip: String) {
    unsafe {
        INIT6.call_once(|| {
            CLIENT_IP = client_ip;
        });
    }
}

fn init_ip(ip: String) {
    unsafe {
        INIT7.call_once(|| {
            IP = ip;
        });
    }
}

fn init_tun_name(tun_name: String) {
    unsafe {
        INIT8.call_once(|| {
            TUN_NAME = tun_name;
        });
    }
}

fn update_secret(secret: String) {
    init_secret(secret);
}

fn get_secret() -> String {
    unsafe {
        let secret_clone = SECRET.clone();
        let secret = secret_clone.unwrap();
        secret
    }
}

fn get_otp() -> u64 {
    unsafe {
        let otp_clone = OTP.clone();
        let otp = otp_clone;
        otp
    }
}

fn get_client_ip() -> String {
    unsafe {
        let client_ip = CLIENT_IP.clone();
        client_ip
    }
}

fn get_ip() -> String {
    unsafe {
        let ip = IP.clone();
        ip
    }
}

fn get_tun_name() -> String {
    unsafe {
        let tun_name = TUN_NAME.clone();
        tun_name
    }
}

fn set_nonblocking(sock_fd: RawFd) -> io::Result<()> {
    let flags =
        fcntl(sock_fd, FcntlArg::F_GETFL).map_err(|e| io::Error::from_raw_os_error(e as i32))?;
    fcntl(
        sock_fd,
        FcntlArg::F_SETFL(OFlag::from_bits_truncate(flags) | OFlag::O_NONBLOCK),
    )
    .map_err(|e| io::Error::from_raw_os_error(e as i32))?;
    Ok(())
}

fn flush_nftables() -> Result<(), io::Error> {
    // Execute the nft command to flush the ruleset
    let output = Command::new("nft").args(&["flush", "ruleset"]).output()?;

    // Check if the command was successful
    if output.status.success() {
        println!("Successfully flushed nftables rules");
        Ok(())
    } else {
        // If there was an error, print the error message
        let error_message = String::from_utf8_lossy(&output.stderr);
        eprintln!("Failed to flush nftables rules: {}", error_message);
        Err(io::Error::new(io::ErrorKind::Other, error_message))
    }
}

/// Function to find the first network interface that is "up"
fn get_first_up_interface() -> Result<Option<String>, Box<dyn Error>> {
    // Run the `ip addr` command and capture the output
    let output = Command::new("ip").arg("addr").output()?;

    // Check if the command was successful
    if !output.status.success() {
        return Err("Failed to execute ip addr command".into());
    }

    // Parse the output as a UTF-8 string
    let output_str = std::str::from_utf8(&output.stdout)?;

    // Split the output into lines and process them
    let mut current_interface: Option<&str> = None;

    for line in output_str.lines() {
        // Look for lines that represent a network interface (they start with a number followed by the interface name)
        if line.contains(": <") {
            // Get the name of the interface (extract part before the colon)
            let parts: Vec<&str> = line.split_whitespace().collect();
            if let Some(iface_name) = parts.get(1) {
                current_interface = Some(iface_name.trim_end_matches(':'));
            }
        }

        // Look for the UP flag
        if line.contains("state UP") && current_interface.is_some() {
            return Ok(Some(current_interface.unwrap().to_string()));
        }
    }

    // If no interface is found, return None
    Ok(None)
}

/// Function to find the IP address of a given interface
fn get_ip_of_interface(interface: &str) -> Result<Option<String>, Box<dyn Error>> {
    // Run the `ip addr` command and capture the output
    let output = Command::new("ip").arg("addr").output()?;

    // Check if the command was successful
    if !output.status.success() {
        return Err("Failed to execute ip addr command".into());
    }

    // Parse the output as a UTF-8 string
    let output_str = std::str::from_utf8(&output.stdout)?;

    let mut is_target_interface = false;

    for line in output_str.lines() {
        // Check if this line refers to the target interface
        if line.contains(&format!("{}:", interface)) {
            is_target_interface = true;
        }

        // If we are at the target interface and find an IP address, return it
        if is_target_interface && line.contains("inet ") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if let Some(ip_with_mask) = parts.get(1) {
                // Split the IP and the mask, returning just the IP part
                let ip = ip_with_mask.split('/').next().unwrap_or("");
                return Ok(Some(ip.to_string()));
            }
        }
    }

    // If no IP is found, return None
    Ok(None)
}

pub struct Trace {
    trace: *mut nftnl_trace,
}

impl Trace {
    pub fn new() -> Self {
        unsafe {
            let trace = nftnl_trace_alloc() as *mut nftnl_trace;
            if trace.is_null() {
                panic!("Failed to allocate trace");
            }
            Trace { trace }
        }
    }

    pub fn free(self) {
        unsafe {
            nftnl_trace_free(self.trace);
        }
    }

    pub fn is_set(&self, type_: u16) -> bool {
        unsafe { nftnl_trace_is_set(self.trace, type_) }
    }

    pub fn get_str(&self, type_: u16) -> Option<String> {
        unsafe {
            let c_str = nftnl_trace_get_str(self.trace, type_);
            if c_str.is_null() {
                None
            } else {
                Some(CStr::from_ptr(c_str).to_string_lossy().into_owned())
            }
        }
    }
}

// Struct for Netlink message
#[repr(C)]
struct Nlmsghdr {
    nlmsg_len: u32,   // Length of the message including this header
    nlmsg_type: u16,  // Type of message
    nlmsg_flags: u16, // Flags
    nlmsg_seq: u32,   // Sequence number
    nlmsg_pid: u32,   // PID of the sending process
}

#[repr(C)]
struct NfqnlMsgVerdictHdr {
    verdict: u32, // The verdict (e.g., NF_ACCEPT, NF_DROP)
    id: u32,      // The packet ID
}

#[repr(C)]
struct NfqnlMsgPacketHdr {
    packet_id: u32,
    hw_protocol: u16,
    hook: u16,
}

fn extract_packet_id(buffer: &[u8]) -> Option<u32> {
    use std::mem;

    // Ensure buffer is large enough to hold Nlmsghdr
    if buffer.len() < mem::size_of::<Nlmsghdr>() {
        eprintln!("Buffer is too small to contain a Netlink message header.");
        return None;
    }

    // Safely read the Nlmsghdr from the buffer
    let nlmsg = unsafe { &*(buffer.as_ptr() as *const Nlmsghdr) };

    // Ensure the buffer is large enough to hold the full message
    if (nlmsg.nlmsg_len as usize) > buffer.len()
        || (nlmsg.nlmsg_len as usize) < mem::size_of::<Nlmsghdr>()
    {
        eprintln!("Invalid Netlink message length.");
        return None;
    }

    // Calculate where the payload starts
    let payload_start = mem::size_of::<Nlmsghdr>();

    // Ensure the buffer has enough data for NfqnlMsgPacketHdr
    if buffer.len() < payload_start + mem::size_of::<NfqnlMsgPacketHdr>() {
        eprintln!("Buffer is too small to contain the Netfilter Queue packet header.");
        return None;
    }

    // Safely read the NfqnlMsgPacketHdr from the payload
    let nfq_packet_hdr =
        unsafe { &*(buffer[payload_start..].as_ptr() as *const NfqnlMsgPacketHdr) };

    // Convert the packet_id to host byte order and return it
    Some(u32::from_be(nfq_packet_hdr.packet_id))
}

fn send_verdict(sock_fd: RawFd, verdict: Verdict, packet_id: u32) {
    let mut msg_verdict: Nlmsghdr = unsafe { std::mem::zeroed() };
    msg_verdict.nlmsg_type = ((NFNL_SUBSYS_QUEUE as u16) << 8) | (NFQNL_MSG_VERDICT as u16);
    msg_verdict.nlmsg_len =
        (std::mem::size_of::<Nlmsghdr>() + std::mem::size_of::<NfqnlMsgVerdictHdr>()) as u32;

    // Create the verdict message (including the packet ID and verdict)
    let mut verdict_msg: NfqnlMsgVerdictHdr = unsafe { std::mem::zeroed() };
    verdict_msg.verdict = verdict as u32;
    verdict_msg.id = packet_id.to_be(); // Convert packet ID to network byte order

    // Create a buffer to hold the message header and the verdict
    let total_size = msg_verdict.nlmsg_len as usize;
    let mut buffer: Vec<u8> = vec![0; total_size];

    unsafe {
        std::ptr::copy_nonoverlapping(
            &msg_verdict as *const _ as *const u8,
            buffer.as_mut_ptr(),
            std::mem::size_of::<Nlmsghdr>(),
        );
        std::ptr::copy_nonoverlapping(
            &verdict_msg as *const _ as *const u8,
            buffer.as_mut_ptr().add(std::mem::size_of::<Nlmsghdr>()),
            std::mem::size_of::<NfqnlMsgVerdictHdr>(),
        );
    }

    let send_result = unsafe { send(sock_fd, buffer.as_ptr() as *const c_void, total_size, 0) };

    if send_result == -1 {
        eprintln!(
            "Failed to send verdict: {}",
            std::io::Error::last_os_error()
        );
    } else {
        println!("Successfully sent verdict.");
    }
}

fn process_nfqueue_packets(queue_index: usize) -> (Vec<u8>, RawFd, Option<u32>) {
    let sock_fd: RawFd = unsafe { socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER) };
    if sock_fd < 0 {
        eprintln!(
            "Failed to create netlink socket: {}",
            std::io::Error::last_os_error()
        );
        return (Vec::new(), -1, None); // Return -1 for error
    }
    let _ = set_nonblocking(sock_fd);
    let mut addr: sockaddr_nl = unsafe { std::mem::zeroed() };
    addr.nl_family = AF_NETLINK as u16;
    addr.nl_pid = 0; // Kernel
                     //MAYBE >>>>//addr.nl_groups = 1 << queue_index; // Queue index can;t be above 31. (let num_queues = 32; //MAX SIZE u32)
    let binary_representation = format!("{:b}", queue_index)
        .parse()
        .expect("Failed to convert string to u32");

    addr.nl_groups = binary_representation;

    let ret = unsafe {
        bind(
            sock_fd,
            &addr as *const sockaddr_nl as *const libc::sockaddr,
            std::mem::size_of::<sockaddr_nl>() as u32,
        )
    };
    if ret < 0 {
        eprintln!(
            "Failed to bind netlink socket: {}",
            std::io::Error::last_os_error()
        );
        unsafe { libc::close(sock_fd) };
        return (Vec::new(), -1, None); // Return -1 for error
    }

    let mut buffer: [u8; 4096] = [0; 4096];

    let recv_len = unsafe { recv(sock_fd, buffer.as_mut_ptr() as *mut c_void, buffer.len(), 0) };
    if recv_len < 0 {
        //eprintln!(
        //    "Failed to receive message: {} Queue {}",
        //    std::io::Error::last_os_error(),
        //    queue_index
        //);
        unsafe { libc::close(sock_fd) };
        return (Vec::new(), -1, None); // Return -1 for error
    }
    exit_program(); //HERE
    if recv_len == 0 {
        eprintln!("Received 0 bytes, connection may be closed.");
        unsafe { libc::close(sock_fd) };
        return (Vec::new(), sock_fd, None);
    }

    let packet_id = extract_packet_id(&buffer);

    let packet_data = &buffer[..recv_len as usize];

    (packet_data.to_vec(), sock_fd, packet_id)
}

fn hkdf_derive_key(initial_key: u64) -> u64 {
    let initial_key_bytes = initial_key.to_be_bytes(); // 8 bytes

    // Use HKDF to derive a longer key
    let hk = Hkdf::<Sha512>::new(None, &initial_key_bytes);
    let mut okm = [0u8; 128]; // 128 bytes output
    hk.expand(&[], &mut okm)
        .expect("OKM generation should not fail");

    let mut hmac = Hmac::<Sha512>::new_from_slice(&okm).expect("HMAC can take key of any size");

    let time = (OffsetDateTime::now_utc().unix_timestamp() / 60).to_be_bytes();
    hmac.update(&time); //TODO: Do better than this in the future.
    let digest = hmac.finalize();
    let bytes = digest.into_bytes();
    let mut truncated_bytes = [0u8; 8];
    truncated_bytes.copy_from_slice(&bytes[..8]);
    u64::from_be_bytes(truncated_bytes)
}

fn generate_fips() -> String {
    let mut rng = rand::thread_rng();
    let secret: Vec<u8> = (0..16).map(|_| rng.gen::<u8>()).collect();
    base32::encode(Alphabet::RFC4648 { padding: false }, &secret)
}

fn format_key(totp: u64) -> Array<u8, typenum::U32> {
    // Convert `u32` to a 4-byte array
    let key_u64_bytes = totp.to_be_bytes(); // Converts u32 to big-endian [u8; 4]

    // Create a 32-byte array and copy the 4-byte key into it
    let mut key_32_bytes = [0u8; 32]; // 32-byte array filled with zeros
    key_32_bytes[..8].copy_from_slice(&key_u64_bytes); // Copy the 4-byte array into the first 4 bytes

    // Convert the 32-byte array to `Array<u8, U32>`
    let key: Array<u8, typenum::U32> = Array::from(key_32_bytes);
    key
}

fn encrypt(data: Vec<u8>, otp: u64) -> Vec<u8> {
    //let mut rng = rand::thread_rng();
    let data = pad(data);
    let data = String::from_utf8(data).unwrap();
    let key: Array<u8, typenum::U32> = format_key(otp);
    let blocks = data.as_bytes().chunks(16).map(|chunk| {
        //TODO: check for padding!
        let mut block = Array::default();
        block.copy_from_slice(chunk);
        block
    });

    // Initialize cipher
    let cipher = Aes256::new(&key);

    // Encrypt the data
    let mut blocks_array: Vec<Array<u8, typenum::U16>> = blocks
        .map(|block| {
            if block.len() != 16 {
                panic!("Invalid block size");
            }
            Array::from(block)
        })
        .collect();

    let mut encrypted_data = Vec::new();

    for block in &mut blocks_array {
        cipher.encrypt_block(block);
        encrypted_data.extend(block.clone());
    }
    encrypted_data
}

fn decrypt(encrypted_data: Vec<u8>, otp: u64) -> Vec<u8> {
    //let key = Array::from([0u8; 32]);
    let key: Array<u8, typenum::U32> = format_key(otp);
    let cipher = Aes256::new(&key);
    let blocks = encrypted_data.chunks(16).map(|chunk| {
        //TODO: check for padding!
        let mut block = Array::default();
        block.copy_from_slice(chunk);
        block
    });

    let mut blocks_array: Vec<Array<u8, typenum::U16>> = blocks
        .map(|block| {
            if block.len() != 16 {
                panic!("Invalid block size");
            }
            Array::from(block)
        })
        .collect();

    let mut decrypted_data = Vec::new();
    for block in &mut blocks_array {
        cipher.decrypt_block(block);
        decrypted_data.extend(block.clone());
    }

    decrypted_data
}

fn pad(data: Vec<u8>) -> Vec<u8> {
    let padding = 16 - (data.len() % 16);
    if padding == 16 {
        return data;
    }

    let mut padded_data = data.clone();
    padded_data.extend(vec![0; padding]);
    padded_data
}

fn generate_totp(secret: String) -> u64 {
    let key =
        base32::decode(Alphabet::RFC4648 { padding: false }, &secret).expect("Invalid secret");
    let interval: u64 = 30; // 30 sec
    let time = (OffsetDateTime::now_utc().unix_timestamp() as u64) / interval;
    let mut mac = Hmac::<Sha512>::new_from_slice(&key).expect("Invalid key length");
    mac.update(&time.to_be_bytes());
    let result = mac.finalize().into_bytes();
    let offset = (result[result.len() - 1] & 0xf) as usize;
    let code = u64::from_be_bytes([
        result[offset],
        result[offset + 1],
        result[offset + 2],
        result[offset + 3],
        result[offset + 4],
        result[offset + 5],
        result[offset + 6],
        result[offset + 7],
    ]) & 0x1FFFFFFFFFFFFFFF;

    code % 1_0000_0000
}

fn set_ipv4_payload(packet: &mut MutableIpv4Packet, payload: &[u8]) {
    let header_len = packet.get_header_length() as usize * 4;
    let total_len = (header_len + payload.len()) as u16;

    // Calculate and set the total length (header length + payload length)
    packet.set_total_length(total_len);

    // Set the payload
    packet.set_payload(payload);

    // Optionally recalculate the checksum
    let checksum = pnet::util::checksum(packet.packet(), 1);
    packet.set_checksum(checksum);
}

fn send_packet(packet: Ipv4Packet, forged_dst_ip: Ipv4Addr) -> Ipv4Packet {
    // takes the machine's request encrypt & zlib processes it into a PDF file for transport.
    let mut base64 = String::new();

    // Parse the packet
    let payload = packet.payload();

    // extract destination ip from the packet
    let dst_from_packet: Ipv4Addr = packet.get_destination();
    let dst_from_packet_slice = dst_from_packet.octets();
    let dst_from_packet_slice: &[u8] = dst_from_packet_slice.borrow();

    //println!("Payload data: {:?}", payload);
    let ipv4_header_len = packet.get_header_length() as usize * 4; // Typical length of IPv4 header
    let datagram = packpdf(payload, &mut base64); // KEEP THAT LINE TRUE.
    let datagram = datagram.borrow();

    // Extract the payload (datagram) to concatenate after the original destination ip.
    let datagram = [dst_from_packet_slice, datagram].concat();
    let datagram: &[u8] = datagram.borrow();

    let buffer_len = ipv4_header_len + datagram.len();

    let mut buffer = vec![0u8; buffer_len];

    let mut new_packet = MutableIpv4Packet::new(&mut buffer[..]).unwrap();

    // Copy fields from original packet to new packet
    new_packet.set_version(packet.get_version());
    new_packet.set_header_length(packet.get_header_length());
    new_packet.set_dscp(packet.get_dscp());
    new_packet.set_ecn(packet.get_ecn());
    new_packet.set_total_length(0);
    new_packet.set_identification(packet.get_identification());
    new_packet.set_flags(packet.get_flags());
    new_packet.set_fragment_offset(packet.get_fragment_offset());
    new_packet.set_ttl(packet.get_ttl());
    new_packet.set_next_level_protocol(packet.get_next_level_protocol());
    new_packet.set_checksum(0);
    new_packet.set_source(packet.get_source());
    new_packet.set_destination(forged_dst_ip);
    new_packet.set_options(&packet.get_options());

    // Replace the old payload with the new one
    set_ipv4_payload(&mut new_packet, datagram); //KEEP THAT LINE TRUE!

    println!(
        "SEND - packet (Length): {:?}",
        new_packet.get_total_length()
    );

    Ipv4Packet::owned(new_packet.packet().to_vec()).unwrap()
}

fn receive_packet(packet: Ipv4Packet) -> Ipv4Packet {
    // process a request from the far-end tun device into a request processed either near or far depending on the request's origin.
    let mut base64 = String::new();

    let payload = packet.payload();

    // Extract original destination for packet from payload's first 4 bytes..
    let original_dst: Ipv4Addr = Ipv4Addr::from([payload[0], payload[1], payload[2], payload[3]]);

    let payload = &payload[4..];

    let _ = packpdf(payload, &mut base64); // KEEP THAT LINE TRUE!

    let mut buffer = vec![0u8; packet.packet().len()];
    let mut new_packet = MutableIpv4Packet::new(&mut buffer[..]).unwrap();

    // Copy fields from original packet to new packet
    new_packet.set_version(packet.get_version());
    new_packet.set_header_length(packet.get_header_length());
    new_packet.set_dscp(packet.get_dscp());
    new_packet.set_ecn(packet.get_ecn());
    new_packet.set_total_length(packet.get_total_length());
    new_packet.set_identification(packet.get_identification());
    new_packet.set_flags(packet.get_flags());
    new_packet.set_fragment_offset(packet.get_fragment_offset());
    new_packet.set_ttl(packet.get_ttl());
    new_packet.set_next_level_protocol(packet.get_next_level_protocol());
    new_packet.set_checksum(packet.get_checksum());
    new_packet.set_source(packet.get_source());
    new_packet.set_destination(original_dst);
    new_packet.set_options(&packet.get_options());

    // Replace the old payload with the new one
    set_ipv4_payload(&mut new_packet, base64.as_bytes()); //KEEP THAT LINE TRUE!

    println!(
        "RECEIVE - packet (Length): {:?}",
        new_packet.get_total_length()
    );

    Ipv4Packet::owned(new_packet.packet().to_vec()).unwrap()
}

fn packpdf(buffer: &[u8], base64: &mut String) -> Vec<u8> {
    let mut page_count = 0; // Page counter

    // Set the page size to Letter (210.0 x 297.0 mm)
    let (doc, mut current_page, current_layer_index) = PdfDocument::new(
        "",
        INITIAL_PAGE_WIDTH,
        INITIAL_PAGE_HEIGHT,
        &format!("Layer {}", page_count),
    );

    // Prepare to add text to the PDF
    let text_content = String::from_utf8_lossy(buffer);
    let font = doc
        .add_builtin_font(BuiltinFont::Helvetica)
        .expect("Failed to add built-in font"); // This returns an IndirectFontRef

    // Start adding text, handling wrapping
    let max_width = EMPTY_LINE_WIDTH - 2.0 * MARGIN; // Width of the text area in mm
    let mut current_y = TOP_PAGE; // Start position from the top of the page

    // Add the initial layer
    let mut current_layer = doc.get_page(current_page).get_layer(current_layer_index); // Access the layer using the index

    // Split the text content by lines
    for line in text_content.lines() {
        let words: Vec<&str> = line.split(' ').collect(); // Split by spaces, preserving them
        let mut current_x = MARGIN; // Reset X position for each new line

        for (i, word) in words.iter().enumerate() {
            // Approximate width in mm (using a rough average for Helvetica)
            let word_width = word.len() as f64 * 2.7056 + 2.7056; // Average width per character in mm

            // Check if adding this word exceeds the max width
            if current_x + word_width > max_width {
                // If it exceeds, move down for the next line
                current_y -= LINE_HEIGHT; // Move down for the next line
                current_x = MARGIN; // Reset X position
            }

            // Use the word in the PDF
            current_layer.use_text(*word, 12.0, Mm(current_x), Mm(current_y), &font);
            current_x += word_width; // Move x by the width of the word

            // Add space between words if not the last word
            if i < words.len() - 1 {
                current_x += 0.3528; // Add space (2.4 mm as an example)
            }
        }

        // Move down for the next line after processing the current line
        current_y -= LINE_HEIGHT;

        // Check if we need to move to a new page if we're out of space
        if current_y < MARGIN {
            processpdf(doc.clone(), base64.borrow_mut());
            // Create a new page
            page_count += 1; // Increment the page counter
            let (new_page, new_layer) = doc.add_page(
                INITIAL_PAGE_WIDTH,
                INITIAL_PAGE_HEIGHT,
                &format!("Layer {}", page_count),
            );
            current_page = new_page; // Update current_page with the new page
            current_layer = doc.get_page(current_page).get_layer(new_layer); // Use the new layer
            current_y = TOP_PAGE; // Reset Y position for the new page
        }
    }

    processpdf(doc.clone(), base64.borrow_mut())
}

fn decode_utf8_safe(bytes: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
    let mut result = String::new();
    let mut i = 0;

    while i < bytes.len() {
        let byte = bytes[i];

        // Handle ASCII (single-byte)
        if byte <= 0x7F {
            result.push(byte as char);
            i += 1;
            continue;
        }

        // Handle two-byte sequences
        if byte >= 0xC2 && byte <= 0xDF {
            if i + 1 < bytes.len() && (bytes[i + 1] >= 0x80 && bytes[i + 1] <= 0xBF) {
                let code_point = ((byte & 0x1F) as u32) << 6 | (bytes[i + 1] & 0x3F) as u32;
                result.push(char::from_u32(code_point).unwrap_or('�')); // Use replacement character for invalid
                i += 2;
                continue;
            } else {
                // Invalid second byte
                result.push('�'); // Use replacement character for the error
                i += 1; // Move on
                continue;
            }
        }

        // Handle three-byte sequences
        if byte >= 0xE0 && byte <= 0xEF {
            if i + 2 < bytes.len()
                && (bytes[i + 1] >= 0x80 && bytes[i + 1] <= 0xBF)
                && (bytes[i + 2] >= 0x80 && bytes[i + 2] <= 0xBF)
            {
                let code_point = ((byte & 0x0F) as u32) << 12
                    | ((bytes[i + 1] & 0x3F) as u32) << 6
                    | (bytes[i + 2] & 0x3F) as u32;
                result.push(char::from_u32(code_point).unwrap_or('�'));
                i += 3;
                continue;
            } else {
                // Invalid sequence
                result.push('�'); // Use replacement character
                i += 1;
                continue;
            }
        }

        // Handle four-byte sequences
        if byte >= 0xF0 && byte <= 0xF4 {
            if i + 3 < bytes.len()
                && (bytes[i + 1] >= 0x80 && bytes[i + 1] <= 0xBF)
                && (bytes[i + 2] >= 0x80 && bytes[i + 2] <= 0xBF)
                && (bytes[i + 3] >= 0x80 && bytes[i + 3] <= 0xBF)
            {
                let code_point = ((byte & 0x07) as u32) << 18
                    | ((bytes[i + 1] & 0x3F) as u32) << 12
                    | ((bytes[i + 2] & 0x3F) as u32) << 6
                    | (bytes[i + 3] & 0x3F) as u32;
                result.push(char::from_u32(code_point).unwrap_or('�'));
                i += 4;
                continue;
            } else {
                // Invalid sequence
                result.push('�'); // Use replacement character
                i += 1;
                continue;
            }
        }

        // If we get here, the byte is invalid
        result.push('�'); // Use replacement character
        i += 1;
    }

    Ok(result)
}

fn decode_hex_text(hex: &str) -> Result<String, Box<dyn std::error::Error>> {
    let bytes = hex::decode(hex)?;
    let text = decode_utf8_safe(&bytes)?;

    Ok(text)
}

fn extract_text_from_pdf_stream(stream: String) -> Result<String, Box<dyn std::error::Error>> {
    let mut extracted_text = String::new();

    for line in stream.lines() {
        if line.contains("Tj") || line.contains("TJ") {
            let mut inside_brackets = false;
            let mut hex_string = String::new();

            for c in line.chars() {
                if c == '<' {
                    inside_brackets = true;
                } else if c == '>' {
                    inside_brackets = false;
                    if !hex_string.is_empty() {
                        let decoded_text = decode_hex_text(&hex_string)?;
                        extracted_text.push_str(&decoded_text);
                        hex_string.clear();
                    }
                } else if inside_brackets {
                    hex_string.push(c);
                }
            }
        }
    }

    Ok(extracted_text)
}

fn processpdf(doc: PdfDocumentReference, base64: &mut String) -> Vec<u8> {
    use lopdf::Object;
    use printpdf::*;
    use std::borrow::Borrow;
    use std::cell::RefCell;
    use std::cell::RefMut;
    use std::io::{self, BufWriter, Write};
    use std::rc::Rc;

    let mut buffer = Vec::new();
    // send the layer over to stdout
    {
        let doc_go = doc.clone();
        // Clone the document reference safely
        let doc_clone: Rc<std::cell::RefCell<PdfDocument>> = doc.document.clone();
        let pdfdoc: &Rc<RefCell<printpdf::PdfDocument>> = doc_clone.borrow();
        let pdfdoc: &RefCell<printpdf::PdfDocument> = pdfdoc.borrow();
        let pdfdoc: RefMut<PdfDocument> = pdfdoc.borrow_mut();
        let inner_document = doc_go.tunnel(&pdfdoc);

        let pages = inner_document.get_pages();

        //eprintln!("After -->: {}", pages.len());

        // Get pages and check if any are available
        if let Some(&last_page) = pages.keys().last() {
            // Get the object ID of the last page
            if let Some(&object_id) = pages.get(&last_page) {
                // Extract page content
                match inner_document.get_page_content(object_id) {
                    Ok(data) => {
                        // Handle the successful result
                        match inner_document.get_dictionary(object_id) {
                            // SEND TO STDOUT.
                            Ok(result) => {
                                let mut document = lopdf::Document::with_version("1.5");
                                let content_stream = lopdf::Stream::new(
                                    result.clone(),
                                    encrypt(data, hkdf_derive_key(get_otp())),
                                )
                                .with_compression(true);

                                let stream_id = document.add_object(content_stream);
                                document.compress();
                                let _ = document.save_to(&mut buffer);
                                if !is_elevated() {
                                    let stdout = io::stdout();
                                    let mut buf_writer = BufWriter::new(stdout.lock());
                                    if let Err(err) = buf_writer.write_all(&buffer) {
                                        eprintln!("Failed to write to stdout: {}", err);
                                    }
                                    if let Err(err) = buf_writer.flush() {
                                        eprintln!("Failed to flush stdout: {}", err);
                                    }
                                    let _ = buf_writer.flush();
                                }
                                document.decompress();
                                // POC bridge ofver to the original from buffer
                                // Print the stream's content
                                //println!("Extracted Content Stream:");
                                // Decode the stream's content to print (use appropriate method if compressed)
                                if let Ok(Object::Stream(ref stream)) =
                                    document.get_object(stream_id)
                                {
                                    let encrypted_content = stream.content.to_vec();

                                    let decrypted;
                                    unsafe {
                                        if IN_SYNC == true {
                                            decrypted = decrypt(
                                                encrypted_content,
                                                hkdf_derive_key(get_otp()),
                                            );
                                        } else {
                                            IN_SYNC = true;
                                            decrypted = decrypt(encrypted_content, get_otp());
                                        }
                                    }
                                    match decode_utf8_safe(&decrypted) {
                                        Ok(lotextstring) => {
                                            match extract_text_from_pdf_stream(lotextstring) {
                                                Ok(original_text) => {
                                                    base64.push_str(&original_text);
                                                }
                                                Err(error) => {
                                                    eprintln!(
                                                            "Failed to convert base64 to original text {}",
                                                            error
                                                        );
                                                }
                                            }
                                            //println!("{}", original_text);
                                        }
                                        Err(error) => {
                                            eprintln!("Failed to convert data to base64 {}", error);
                                        }
                                    }
                                }
                            }
                            Err(error) => {
                                eprintln!("Failed to extract dictionary: {}", error);
                            }
                        }
                    }
                    Err(error) => {
                        eprintln!("Failed to extract page content: {}", error);
                    }
                }
            } else {
                eprintln!("Failed to get object ID for the last page.");
            }
        } else {
            eprintln!("No pages available in the document.");
        }
    }
    buffer
}

fn valid_ip(ip: String) -> bool {
    match ip.parse::<IpAddr>() {
        Ok(_) => return true,
        Err(_) => return false,
    };
}

fn get_available_subnet() -> Option<String> {
    let tun_name = get_tun_name();
    let dev: &str = tun_name.borrow();
    let first_if_up = get_first_up_interface().unwrap().unwrap();
    let check_ip = get_ip_of_interface(&first_if_up).unwrap().unwrap();
    let check_ip = check_ip.parse::<Ipv4Addr>().unwrap();
    // Define the non-routable zones
    let non_routable_zones = [
        ("10.0.0.0/8", "10.1.1.1", "255.255.255.255"),
        ("172.16.0.0/12", "172.16.0.1", "255.255.255.255"),
        ("192.168.0.0/16", "192.168.1.1", "255.255.255.255"),
    ];

    // Get a list of network interfaces and their IP addresses
    let output = Command::new("ip")
        .arg("addr")
        .output()
        .expect("Failed to execute ip command");

    let output_str = String::from_utf8(output.stdout).expect("Failed to convert output to string");
    let lines: Vec<&str> = output_str.lines().collect();

    // Iterate through the non-routable zones and find the first available subnet
    for (_zone, address, netmask) in non_routable_zones.iter() {
        // Parse the zone's IP address
        let zone_ip = address
            .split('.')
            .map(|x| x.parse::<u8>().unwrap())
            .collect::<Vec<u8>>();

        // Check every possible IP in the subnet
        for i in 1..=255 {
            let ip = [zone_ip[0], zone_ip[1], zone_ip[2], i];

            // Check if the IP is already in use
            let ip_addr = Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]);
            let mut ip_in_use = false;

            let mut ifname = "";
            for line in lines.iter() {
                if line.contains("inet") && !line.contains("inet6") {
                    // IPV4 only
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if check_ip
                        == parts[1]
                            .split('/')
                            .next()
                            .unwrap()
                            .parse::<Ipv4Addr>()
                            .unwrap()
                    {
                        ifname = parts.last().unwrap();
                    }
                    let existing_ip_addr = parts[1].split('/').next().unwrap();
                    let existing_ip_addr = existing_ip_addr.parse::<Ipv4Addr>().unwrap();
                    if existing_ip_addr == ip_addr {
                        ip_in_use = true;
                        break;
                    }
                }
            }

            // If the IP is not in use, return it
            if !ip_in_use {
                return Some(format!(
                    "{}.{}.{}.{} {} {} {}.{}.{}.0/24 {}",
                    ip[0], ip[1], ip[2], ip[3], netmask, dev, ip[0], ip[1], ip[2], ifname
                ));
            }
        }
    }

    None
}

fn get_available_tun_name() -> String {
    let mut name = "tun0".to_string();
    let mut index = 0;

    loop {
        // Check if the TUN device is already in use
        let output = Command::new("ip")
            .arg("link")
            .arg("show")
            .arg(&name)
            .output();

        match output {
            Ok(output) => {
                // Convert the output to a string
                let stderr = String::from_utf8(output.stderr).unwrap_or_default();
                // Check if the output contains "does not exist"
                if stderr.contains("does not exist.") {
                    // TUN device is not in use, return the name
                    return name;
                }
            }
            Err(e) => {
                eprintln!("Failed to execute command: {}", e);
            }
        }

        // TUN device is in use, try the next name
        index += 1;
        name = format!("tun{}", index);
    }
}

fn exit_program() {
    exit(1);
}

fn print_error(tun_name: String, error: std::io::Error) {
    eprintln!("Failed to write to tun device {}: {}", tun_name, error);
}

fn set_route(routable: &str, dev: &str) {
    let _output = Command::new("ip")
        .arg("route")
        .arg("add")
        .arg(routable)
        .arg("dev")
        .arg(dev)
        .output()
        .expect("Failed to add route for tun interface");
}

fn del_route(routable: &str, dev: &str) {
    let _output = Command::new("ip")
        .arg("route")
        .arg("del")
        .arg(routable)
        .arg("dev")
        .arg(dev)
        .output()
        .expect("Failed to remove route for tun interface");
}

fn set_nfqueue_chain(interface: &str) {
    // Set up iptables rule to intercept packets
    println!("Setting up NFQUEUE chain for interface {}", interface);
    let _output = Command::new("iptables")
        .args(&[
            "-t",
            "raw",
            "-A",
            "OUTPUT",
            "-o",
            interface,
            "-p",
            "ALL",
            "-j",
            "NFQUEUE",
            "--queue-balance",
            "0:55",
        ])
        .output()
        .expect("Failed to execute iptables command");
}
// Function to forward packets from TUN interface to the raw socket
fn send_to_raw_socket(packet: Ipv4Packet, raw_socket: RawFd) -> Result<(), String> {
    let dest_addr: sockaddr_ll = sockaddr_ll {
        sll_family: AF_PACKET as u16,
        sll_protocol: 0x0800, // ETH_P_IP (IP packet)
        sll_ifindex: 0,       // Modify based on your setup
        sll_hatype: 0,
        sll_pkttype: 0,
        sll_halen: 0,
        sll_addr: [0; 8], // Not used since we're sending directly
    };

    // Send the packet via the raw socket
    let send_len = unsafe {
        sendto(
            raw_socket,
            packet.packet().as_ptr() as *const c_void,
            packet.packet().len(),
            0,
            &dest_addr as *const _ as *const sockaddr,
            std::mem::size_of::<sockaddr_ll>() as u32,
        )
    };

    if send_len < 0 {
        return Err("Failed to send packet through raw socket".to_string());
    }

    Ok(())
}

fn send_to_tun_interface(
    packet_data: Vec<u8>,
    tun: Arc<Mutex<dyn Device<Queue = Queue>>>,
    queue_index: usize,
) -> Result<(), String> {
    let mut tun_locked = tun.lock().unwrap();
    let queue = tun_locked.queue(queue_index).unwrap();

    queue
        .write(&packet_data)
        .map_err(|e| format!("Error writing to TUN: {}", e))?;
    queue
        .flush()
        .map_err(|e| format!("Error flushing TUN queue: {}", e))?;

    Ok(())
}

fn process_tun(
    tun: Arc<Mutex<dyn Device<Queue = Queue>>>,
    raw_socket: RawFd,
    tun_address: Ipv4Addr,
    peer_ip: Ipv4Addr,
    queue_index: usize,
) {
    let mut buffer = [0u8; 1504];

    let mut tun_locked = tun.lock().unwrap();
    let queue = tun_locked.queue(queue_index).unwrap();
    println!("Queue {} ready", queue_index);

    match queue.read(&mut buffer) {
        Ok(n) => {
            let _ = queue.flush();

            if n > 0 {
                if let Some(packet) = Ipv4Packet::new(&buffer[..n]) {
                    let dst_ip = packet.get_destination();
                    let src_ip = packet.get_source();

                    if src_ip != Ipv4Addr::new(0, 0, 0, 0) {
                        if dst_ip == tun_address {
                            let received_packet = receive_packet(packet);
                            if let Err(e) = send_to_raw_socket(received_packet, raw_socket) {
                                eprintln!("Error sending packet to raw socket: {}", e);
                            }
                        } else {
                            let sent_packet = send_packet(packet, peer_ip);
                            if let Err(e) = queue.write(sent_packet.packet()) {
                                print_error(get_tun_name(), e);
                            }
                            let _ = queue.flush();
                        }
                    }
                }
            }
        }
        Err(e) => {
            eprintln!("Failed to read from queue: {}", e);
        }
    }
}

fn process_local(
    tun: Arc<Mutex<dyn Device<Queue = Queue>>>,
    packet_data: Vec<u8>,
    queue_index: usize,
) {
    if let Err(e) = send_to_tun_interface(packet_data, Arc::clone(&tun), queue_index) {
        eprintln!("Error sending packet to TUN interface: {}", e);
    }
}

fn networked(ip: Ipv4Addr, client_ip: Option<String>, cleanup_receiver: Arc<Mutex<Receiver<()>>>) {
    init_tun_name(get_available_tun_name());
    let available_subnet = get_available_subnet();

    if let Some(subnet) = available_subnet {
        let mut config = tun::Configuration::default();
        let parts: Vec<&str> = subnet.split_whitespace().collect();
        let netmask: Ipv4Addr = parts[1].parse().expect("Invalid IP address format");
        let address: Ipv4Addr = parts[0].parse().expect("Invalid IP address format");
        let broadcast: Ipv4Addr = "255.255.255.255"
            .parse()
            .expect("Invalid IP address format");
        let num_queues = 56;
        let tun_name = get_tun_name();

        // TUN device configuration
        if is_server() {
            config
                .address(address)
                .netmask(netmask)
                .mtu(1500)
                .name(&tun_name)
                .destination(ip)
                .queues(num_queues)
                .broadcast(broadcast)
                .up();
        } else {
            let client_ip = client_ip.clone().unwrap();
            let client_ip: Ipv4Addr = client_ip.parse().expect("Invalid IP address format");
            config
                .address(client_ip)
                .netmask(netmask)
                .mtu(1500)
                .name(&tun_name)
                .destination(ip)
                .queues(num_queues)
                .broadcast(broadcast)
                .up();
        }

        let ifname = parts[2];
        let routable = parts[3];
        let originif = parts[4];
        set_route(routable, ifname);
        set_nfqueue_chain(originif);
        init_iface(ifname.to_string());
        init_routed(routable.to_string());

        // Logging
        if !is_server() {
            println!(
                "TUN device created: {} --> local[{}] <--> peer[{}]",
                &tun_name,
                client_ip.unwrap(),
                &ip
            );
        } else {
            println!(
                "TUN device created: {} --> local[{}] <--> peer[{}]\nDon't forget to use --otp {} on the client within 30 sec.",
                &tun_name,
                &subnet,
                &ip,
                get_otp()
            );
        }

        let dev = Arc::new(Mutex::new(tun::create(&config).unwrap()));
        let running = Arc::new(AtomicBool::new(true));

        while running.load(Ordering::SeqCst) {
            // Create handles for threads
            let mut nfqueue_handles = Vec::new();
            for i in 0..num_queues {
                // Clone the Arc before moving it into the closure
                let dev_clone = Arc::clone(&dev);
                let cleanup = Arc::clone(&cleanup_receiver);
                // Set up the NFQUEUE packet processing
                let nfqueue_handle = {
                    thread::spawn(move || {
                        let mut stole_packet: bool = false;
                        let (packet_data, raw_socket, packet_id_opt) = process_nfqueue_packets(i);
                        let dev_clone_ingress = Arc::clone(&dev_clone);
                        process_tun(dev_clone_ingress, raw_socket, address, ip, i);
                        if packet_data.len() > 0 {
                            let dev_clone_egress = Arc::clone(&dev_clone);
                            process_local(dev_clone_egress, packet_data, i);
                            if let Some(packet_id) = packet_id_opt {
                                send_verdict(raw_socket, Verdict::NfStolen, packet_id);
                            } else {
                                eprintln!("Failed to extract packet ID.");
                            }
                            stole_packet = true;
                        }
                        if !stole_packet {
                            if let Some(packet_id) = packet_id_opt {
                                send_verdict(raw_socket, Verdict::NfAccept, packet_id);
                            } else {
                                eprintln!("Failed to extract packet ID.");
                            }
                        }
                        // close the raw socket
                        unsafe {
                            close(raw_socket);
                        }
                    })
                };

                nfqueue_handles.push(nfqueue_handle);
                // Check for cleanup signal
                if cleanup.lock().unwrap().try_recv().is_ok() {
                    break;
                }
            }

            // Wait for all NFQUEUE threads to finish
            for handle in nfqueue_handles {
                handle.join().expect("NFQUEUE thread panicked");
            }
        }
    } else {
        eprintln!("No available subnet found");
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a channel for cleanup notifications
    let (cleanup_sender, cleanup_receiver) = channel();

    // Wrap the sender in an Arc<Mutex<>> to share it safely across threads
    let shared_state = Arc::new(Mutex::new(SharedState { cleanup_sender }));

    // Ctrl+C signal handler
    {
        let shared_state = Arc::clone(&shared_state);
        ctrlc::set_handler(move || {
            println!("Received Ctrl+C, shutting down...");
            let _ = shared_state.lock().unwrap().cleanup_sender.send(());
            cleanup_and_exit();
        })
        .expect("Error setting Ctrl+C handler");
    }

    // Custom panic hook for resource cleanup
    {
        let shared_state = Arc::clone(&shared_state);
        std::panic::set_hook(Box::new(move |info| {
            eprintln!("Panic occurred: {:?}", info);
            let _ = shared_state.lock().unwrap().cleanup_sender.send(());
            cleanup_and_exit();
        }));
    }

    let mut base64 = String::new();
    if is_elevated() {
        let switches = clap::Command::new("tunpdf")
            .version("0.1")
            .author("jordanlegare4@gmail.com")
            .about("tunpdf a pdf encapsulation for point-to-point networks implementation.")
            .arg(
                Arg::new("ip")
                    .help("The IP address of the peer")
                    .required(true)
                    .action(ArgAction::Set)
                    .short('i')
                    .long("ip")
                    .value_name("IP"),
            )
            .arg(
                Arg::new("client_ip")
                    .help("The LOCAL IP address of the CLIENT peer on the server's subnet")
                    .required(false)
                    .action(ArgAction::Set)
                    .short('c')
                    .long("client_ip")
                    .value_name("CLIENT_IP"),
            )
            .arg(
                Arg::new("otp")
                    .help("The OTP from the SERVER (Client Peer Mode)")
                    .required(false)
                    .action(ArgAction::Set)
                    .short('o')
                    .long("otp")
                    .value_name("OTP"),
            );
        let mut cloned_switches = switches.clone();

        let arguments = switches.get_matches();

        update_secret(generate_fips());
        if let Some(mut otp) = arguments.try_get_raw("otp").ok().flatten() {
            println!("Running in CLIENT peer mode...");
            let otp = otp.next().unwrap().to_str().unwrap();
            init_otp(otp.parse::<u64>().expect("ERROR parsing OTP!"));
            match arguments.try_get_raw("client_ip") {
                Ok(Some(mut ip_client)) => {
                    if let Some(ip) = ip_client.next() {
                        init_client_ip(String::from(ip.to_str().unwrap()));
                    }
                }
                Ok(None) => {
                    println!("Please use switch --client_ip [some valid server subnet ip]");
                    exit_program();
                }
                Err(error) => {
                    println!(
                        "Please use switch --client_ip [some valid server subnet ip]-->Error:{}",
                        error
                    );
                    exit_program();
                }
            }
        } else {
            init_server();
            println!("Running in SERVER peer mode...");
            init_otp(generate_totp(get_secret()));
        }

        match arguments.try_get_raw("ip") {
            Ok(ip_option) => {
                init_ip(String::from(
                    ip_option.unwrap().next().unwrap().to_str().unwrap(),
                ));
                let ip = get_ip();
                if valid_ip(ip.clone()) || ip.clone() == String::from("localhost") {
                    let ip = ip.parse().expect("Invalid IP address format");
                    if is_server() {
                        networked(ip, None, Arc::new(Mutex::new(cleanup_receiver)));
                    } else {
                        networked(
                            ip,
                            Some(get_client_ip()),
                            Arc::new(Mutex::new(cleanup_receiver)),
                        );
                    }
                } else {
                    println!("Please enter a valid ip address.");
                    let _ = cloned_switches.print_long_help();
                }
            }
            Err(error) => {
                eprintln!("{}", error);
                let _ = cloned_switches.print_long_help();
            }
        }
    } else {
        update_secret(generate_fips());
        let mut buffer = Vec::new();
        let stdin = io::stdin();
        let mut handle = stdin.lock();
        // Read the entire stdin into the buffer
        handle.read_to_end(&mut buffer)?;

        // Check if stdin is empty
        if buffer.is_empty() {
            println!("No input provided");
            return Ok(());
        }

        packpdf(buffer.borrow(), &mut base64);

        // Wrap the File in a BufWriter and save the document
        let mut file = File::create("recovered.base64")?;
        file.write_all(base64.as_bytes())?;

        //let mut pdffile = File::create("output.pdf")?;
        //let mut buf_writer = std::io::BufWriter::new(&mut pdffile);
        //let _ = doc.save(&mut buf_writer);

        //println!("PDF generated successfully with {} page(s).", page_count);
    }
    Ok(())
}
