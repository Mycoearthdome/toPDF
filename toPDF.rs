extern crate aes;
extern crate base32;
extern crate clap;
extern crate hex;
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
use hmac::{Hmac, Mac};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::Packet;
use printpdf::*;
use rand::seq::SliceRandom;
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
static mut SECRET: Option<String> = None;

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

fn generate_fips() -> String {
    const BASE64_ALPHABET: &[u8] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    // Create a random number generator
    let length: usize = 44;
    let mut rng = rand::thread_rng();
    // Generate a random string of the specified length
    (0..length)
        .map(|_| BASE64_ALPHABET.choose(&mut rng).unwrap()) // Choose a random character from the alphabet
        .map(|&byte| byte as char) // Convert the byte to char
        .collect() // Collect into a String
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
/*
fn test_encryption() -> bool {
    let mut original = String::from("TEST HELLO WORLD! ENCRYPTION");

    let padding = original.len() % 16;
    //println!("{}", padding);
    if padding > 0 {
        for _ in 0..(16 - padding) {
            original += " ";
        }
    }

    let otp = generate_totp(SECRET);
    let encrypted = encrypt(original.into_bytes(), otp);

    println!(
        "ENCRYPTED:{:#?}",
        String::from_utf8_lossy(encrypted.borrow())
    );

    let otp = generate_totp(SECRET);
    let decrypted = decrypt(encrypted, otp);

    println!("DECRYPTED:{:#?}", String::from_utf8(decrypted));

    true
}
*/
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

fn send(packet: Ipv4Packet) -> Vec<u8> {
    // takes the machine's request encrypt & zlib processes it into a PDF file for transport.
    let mut base64 = String::new();

    // Parse the packet

    // Extract the payload (datagram)
    let payload = packet.payload();
    //println!("Payload data: {:?}", payload);

    let datagram = packpdf(payload, &mut base64);
    let datagram = datagram.borrow();

    // Create a mutable packet
    let mut new_packet = MutableIpv4Packet::owned(packet.packet().to_vec()).unwrap();

    // Set headers (you can copy from the original or modify them)
    new_packet.set_source(packet.get_source());
    new_packet.set_destination(packet.get_destination());
    new_packet.set_next_level_protocol(IpNextHeaderProtocols::Udp);

    // Replace the old payload with the new one
    new_packet.set_payload(datagram);

    // Now, `new_packet` contains the modified IP packet
    new_packet.packet().to_vec()
}

fn receive(packet: Ipv4Packet) -> Vec<u8> {
    // process a request from the far-end tun device into a request processed either near or far depending on the request's origin.
    let mut base64 = String::new();

    let payload = packet.payload();

    let _ = packpdf(payload, &mut base64);

    let mut new_packet = MutableIpv4Packet::owned(packet.packet().to_vec()).unwrap();

    // Set headers (you can copy from the original or modify them)
    new_packet.set_source(packet.get_source());
    new_packet.set_destination(packet.get_destination());
    new_packet.set_next_level_protocol(IpNextHeaderProtocols::Udp);

    // Replace the old payload with the new one
    new_packet.set_payload(base64.as_bytes());

    new_packet.packet().to_vec()
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
                                    encrypt(data, generate_totp(get_secret())),
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

                                    let decrypted =
                                        decrypt(encrypted_content, generate_totp(get_secret()));

                                    //let mut stream = stream.clone();
                                    //stream.content.clone_from(&decrypted);

                                    //let content = stream
                                    //    .decode_content()
                                    //    .expect("Failed to decode stream content");
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
        ("10.0.0.0/8", "10.0.0.1", "255.255.255.0"),
        ("172.16.0.0/12", "172.16.0.1", "255.240.0.0"),
        ("192.168.0.0/16", "192.168.0.1", "255.255.0.0"),
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
            for line in lines.iter() {
                if line.contains("inet") && !line.contains("inet6") {
                    //IPV4 only
                    let parts: Vec<&str> = line.split_whitespace().collect();
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
                    "{}.{}.{}.{} {}",
                    ip[0], ip[1], ip[2], ip[3], netmask
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

fn networked(secret: String, ip: &str) {
    let available_subnet = get_available_subnet();

    update_secret(secret);

    if let Some(subnet) = available_subnet {
        let tun_name = get_available_tun_name();
        let mut config = tun::Configuration::default();
        let parts: Vec<&str> = subnet.split_whitespace().collect();
        config
            .address(parts[0])
            .netmask(parts[1])
            .mtu(1500)
            .name(&tun_name)
            .destination(ip);

        // Create the TUN device
        match Device::new(&config) {
            Ok(dev) => {
                let dev = Arc::new(Mutex::new(dev));
                println!(
                    "TUN device created: {} --> local[{}] <--> peer[{}]",
                    &tun_name, &subnet, &ip
                );

                // Main loop for packet processing
                panic::catch_unwind(|| {
                    let mut buf = [0u8; 1504];

                    loop {
                        let nbytes = match dev.lock().unwrap().read(&mut buf) {
                            Ok(n) => n,
                            Err(e) => {
                                eprintln!("Failed to read from TUN device: {}", e);
                                continue;
                            }
                        };

                        if let Some(packet) = Ipv4Packet::new(&buf[..nbytes]) {
                            let dst_ip = packet.get_destination();

                            if dst_ip.to_string() == parts[0] {
                                // Ingress traffic (from network to TUN interface)
                                let decoded_packet = receive(packet);
                                if let Err(e) =
                                    dev.lock().unwrap().write_all(&decoded_packet.borrow())
                                {
                                    print_error(&tun_name, e);
                                }
                            } else {
                                //println!("Egress traffic (from machine): Src IP: {}, Dst IP: {}", src_ip, dst_ip);
                                let sent_packet = send(packet);
                                if let Err(e) = dev.lock().unwrap().write_all(&sent_packet.borrow())
                                {
                                    print_error(&tun_name, e);
                                }
                            }
                        }
                    }
                })
                .unwrap_or_else(|_| {
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
    //test_encryption();
    //std::process::exit(0);

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
            );
        let mut cloned_switches = switches.clone();

        let arguments = switches.get_matches();

        update_secret(generate_fips());
        match arguments.try_get_raw("ip") {
            Ok(ip_option) => {
                let ip = ip_option.unwrap().next().unwrap().to_str().unwrap();
                if valid_ip(ip) {
                    networked(get_secret(), ip);
                } else {
                    if ip == "localhost" {
                        networked(get_secret(), ip);
                    } else {
                        println!("Please enter a valid ip address.");
                        let _ = cloned_switches.print_long_help();
                    }
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
