extern crate aes;
extern crate base32;
extern crate clap;
extern crate ctrlc;
extern crate hex;
extern crate hkdf; //TODO:FORGE THE UDP TOTAL LENGTH = packet size - headers(20 bytes)
extern crate hmac;
extern crate libc;
extern crate lopdf;
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
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::Packet;
use printpdf::*;
use rand::Rng;
use sha2::Sha512;

use std::borrow::{Borrow, BorrowMut};
use std::fs::File;
use std::io::Write;
use std::io::{self, Read};
use std::net::{IpAddr, Ipv4Addr};
use std::panic;
use std::process;
use std::process::Command;
use std::sync::{Arc, Mutex, Once};
use time::OffsetDateTime;
use tun::platform::Device;

// Set the page size to Letter (210.0 x 297.0 mm)
const MARGIN: f64 = 2.4; // Margin in mm DEFAULT:2.4 for whole page.
const LINE_HEIGHT: f64 = 6.0; // Line height in mm
const INITIAL_PAGE_WIDTH: Mm = Mm(210.0);
const INITIAL_PAGE_HEIGHT: Mm = Mm(80.0); // DEFAULT:297.0
const EMPTY_LINE_WIDTH: f64 = 210.0;
const TOP_PAGE: f64 = 80.0; //DEFAULT:297.0 -12.0

static INIT: Once = Once::new();
static INIT2: Once = Once::new();
static INIT3: Once = Once::new();
static INIT4: Once = Once::new();
static INIT5: Once = Once::new();
static mut SECRET: Option<String> = None;
static mut OTP: u64 = 0;
static mut IN_SYNC: bool = false;
static mut SERVER: bool = false;
static mut IFACE: String = String::new();
static mut ROUTED: String = String::new();

#[cfg(target_family = "unix")]
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
    packet.set_total_length(total_len.to_be());

    // Set the payload
    packet.set_payload(payload);

    // Optionally recalculate the checksum
    let checksum = pnet::util::checksum(packet.packet(), 1);
    packet.set_checksum(checksum);
}

fn send(packet: Ipv4Packet, forged_dst_ip: Ipv4Addr) -> Ipv4Packet {
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

    Ipv4Packet::owned(new_packet.packet().to_vec()).unwrap()
}

fn receive(packet: Ipv4Packet) -> Ipv4Packet {
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

fn valid_ip(ip: &str) -> bool {
    match ip.parse::<IpAddr>() {
        Ok(_) => return true,
        Err(_) => return false,
    };
}

fn get_available_subnet() -> Option<String> {
    // Define the non-routable zones
    let non_routable_zones = [
        ("10.0.0.0/8", "10.0.0.1", "255.255.255.255"),
        ("172.16.0.0/12", "172.16.0.1", "255.255.255.255"),
        ("192.168.0.0/16", "192.168.0.1", "255.255.255.255"),
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
            let mut dev = "";
            for line in lines.iter() {
                if line.contains("inet") && !line.contains("inet6") {
                    //IPV4 only
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    dev = *parts.last().unwrap();
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
                    "{}.{}.{}.{} {} {} {}.{}.{}.0/24",
                    ip[0], ip[1], ip[2], ip[3], netmask, dev, ip[0], ip[1], ip[2]
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
    process::exit(1);
}

fn print_error(tun_name: &str, error: std::io::Error) {
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

fn networked(ip: &str, client_ip: Option<&str>) {
    let available_subnet = get_available_subnet();
    if let Some(subnet) = available_subnet {
        let tun_name = get_available_tun_name();
        let mut config = tun::Configuration::default();
        let parts: Vec<&str> = subnet.split_whitespace().collect();
        if is_server() {
            config
                .address(parts[0])
                .netmask(parts[1])
                .mtu(1500)
                .name(&tun_name)
                .destination(ip)
                .up();
        } else {
            config
                .address(client_ip.unwrap())
                .netmask(parts[1])
                .mtu(1500)
                .name(&tun_name)
                .destination(ip)
                .up();
        }

        // Create the TUN device
        match Device::new(&config) {
            Ok(dev) => {
                let dev = Arc::new(Mutex::new(dev));
                if !is_server() {
                    println!(
                        //Client Peer Mode.
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
                let ifname = parts[2];
                let routable = parts[3];
                set_route(routable, ifname);
                //if_up(&tun_name);
                init_iface(ifname.to_string());
                init_routed(routable.to_string());
                //
                // Main loop for packet processing
                panic::catch_unwind(|| {
                    let mut buf = [0u8; 1504];
                    let mut ip_bytes: [u8; 4] = [0; 4];
                    let parts: Vec<&str> = ip.split('.').collect();
                    for (i, part) in parts.iter().enumerate() {
                        ip_bytes[i] = part.parse::<u8>().unwrap();
                    }

                    loop {
                        let nbytes = match dev.lock().unwrap().read(&mut buf) {
                            Ok(n) => n,
                            Err(e) => {
                                eprintln!("Failed to read from TUN device: {}", e);
                                continue;
                            }
                        };

                        if nbytes > 0 {
                            if let Some(packet) = Ipv4Packet::new(&buf[..nbytes]) {
                                let dst_ip = packet.get_destination();
                                let src_ip = packet.get_source();

                                if src_ip.to_string() != "0.0.0.0" {
                                    if dst_ip.to_string() == parts[0] {
                                        // Ingress traffic (from network to TUN interface)
                                        let decoded_packet = receive(packet);
                                        if let Err(e) =
                                            dev.lock().unwrap().write(decoded_packet.packet())
                                        {
                                            print_error(&tun_name, e);
                                        }
                                    } else {
                                        //println!("Egress traffic (from machine): Src IP: {}, Dst IP: {}", src_ip, dst_ip);
                                        let sent_packet = send(packet, Ipv4Addr::from(ip_bytes));
                                        if let Err(e) =
                                            dev.lock().unwrap().write(sent_packet.packet())
                                        {
                                            print_error(&tun_name, e);
                                        }
                                    }
                                }
                            }
                        }
                    }
                })
                .unwrap_or_else(|_| {
                    del_route(routable, ifname);
                    exit_program();
                });
            }
            Err(error) => {
                eprintln!("Error creating TUN device: {}", error);
            }
        }
    } else {
        eprintln!("No available subnet found");
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    ctrlc::set_handler(move || {
        println!("Received SIGINT, exiting...");
        unsafe {
            del_route(ROUTED.borrow(), IFACE.borrow());
        }
        exit_program()
    })
    .expect("Error setting Ctrl-C handler");

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
        let mut client_ip = "";
        update_secret(generate_fips());
        if let Some(mut otp) = arguments.try_get_raw("otp").ok().flatten() {
            println!("Running in CLIENT peer mode...");
            let otp = otp.next().unwrap().to_str().unwrap();
            init_otp(otp.parse::<u64>().expect("ERROR parsing OTP!"));
            match arguments.try_get_raw("client_ip") {
                Ok(Some(mut ip_client)) => {
                    if let Some(ip) = ip_client.next() {
                        client_ip = ip.to_str().unwrap();
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
                let ip = ip_option.unwrap().next().unwrap().to_str().unwrap();
                if valid_ip(ip) || ip == "localhost" {
                    if is_server() {
                        networked(ip, None);
                    } else {
                        networked(ip, Some(client_ip));
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
