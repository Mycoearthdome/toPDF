extern crate libc;
extern crate nix;
extern crate sysinfo;

const LIME_MODULE: &str = "/home/jordan/Documents/LiME/lime-6.9.3-tsurugi.ko";
const MEMORY_FILE: &str = "memfile";
const PAGE_SIZE: u64 = 4096;

use std::convert::TryInto;
use std::fs::exists;
use std::fs::File;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread;
use std::time::Duration;
use sysinfo::System;

fn find_child_processes(parent_pid: i32) -> Vec<i32> {
    let mut system = System::new_all();
    system.refresh_all();

    let mut child_processes = Vec::new();

    for process in system.processes() {
        if let Some(parent) = process.1.parent() {
            if parent.as_u32() as i32 == parent_pid {
                child_processes.push(process.0.as_u32() as i32);
            }
        }
    }

    child_processes
}

fn launcher() -> (u32, String, u32) {
    let (tx_stdout, rx_stdout) = mpsc::channel();
    let (tx_pid, rx_pid) = mpsc::channel();
    let mut captured_output = Vec::new();

    thread::spawn(move || {
        let mut strace = Command::new("strace")
            .arg("-s")
            .arg("100")
            .arg("-o")
            .arg("/dev/stdout")
            .arg("-e")
            .arg("inject=sendto:signal=SIGSTOP")
            .arg("-e")
            .arg("raw=sendto")
            .arg("-X")
            .arg("raw")
            .arg("-x")
            .arg("nft")
            .arg("add")
            .arg("table")
            .arg("raw_packets")
            .stdout(Stdio::piped()) // Capture stdout
            .stderr(Stdio::piped()) // Capture stderr
            .spawn()
            .expect("Failed to execute strace");
        tx_pid.send(strace.id()).expect("Failed to send strace PID");
        let stdout = strace.stdout.take().expect("Failed to capture stdout");
        let stderr = strace.stderr.take().expect("Failed to capture stderr");
        let reader = BufReader::new(stdout);
        let mut stderr_reader = BufReader::new(stderr);

        for line in reader.lines() {
            match line {
                Ok(line) => {
                    if let Err(_) = tx_stdout.send(line) {
                        break; // Channel closed
                    }
                }
                Err(e) => {
                    eprintln!("Error reading line: {}", e); // Print error
                    break; // Error reading line
                }
            }
        }

        // Read and print any error messages
        let mut error_message = String::new();
        while stderr_reader.read_line(&mut error_message).unwrap() > 0 {
            println!("Error message: {}", error_message);
            error_message.clear(); // Clear for next read
        }
    });

    let strace_pid = rx_pid.recv().expect("Failed to receive strace PID");
    let timeout = Duration::from_secs(1);

    loop {
        match rx_stdout.recv_timeout(timeout) {
            Ok(output) => {
                captured_output.push(output);
            }
            Err(RecvTimeoutError::Timeout) => {
                break;
            }
            Err(RecvTimeoutError::Disconnected) => {
                println!("strace process finished, exiting.");
                break;
            }
        }
    }
    let mut virtual_address = "".to_string();
    let mut length = 0;
    for line in captured_output {
        if line.contains("sendto") {
            println!("{}", line);
            let parts: Vec<&str> = line.split(", ").collect();
            if parts.len() > 1 {
                match u32::from_str_radix(&parts[2][2..], 16) {
                    Ok(len) => length = len,
                    Err(e) => eprintln!("Failed to parse length: {}", e),
                }
                virtual_address = parts[1].to_string();
                break;
            }
        }
    }

    //println!("PID-->{:?}", find_child_processes(strace_pid as i32)[0]);
    (
        find_child_processes(strace_pid as i32)[0] as u32,
        virtual_address,
        length,
    )
}

fn launch_xxd(physical_address: u64, length: u32, memory_file: String) -> Vec<u8> {
    println!("Studying memory dump...");
    println!("xxd -s {} -l {} {}", physical_address, length, memory_file);
    let length_str = length.to_string();
    let xxd = Command::new("xxd")
        .arg("-s")
        .arg(physical_address.to_string())
        .arg("-l")
        .arg(length_str)
        .arg("-p")
        .arg(memory_file)
        .output()
        .expect("Failed to execute xxd");

    xxd.stdout
}

fn dump_raw_ram(path_to_lime_module: String, memfile: String) {
    println!("Dumping raw RAM to file: {}", memfile);
    println!("insmod {} path={} format=raw", path_to_lime_module, memfile);
    if exists(path_to_lime_module.clone()).unwrap() {
        let mut child = Command::new("insmod")
            .arg(path_to_lime_module)
            .arg(format!("path={}", memfile))
            .arg("format=raw")
            .spawn()
            .expect("Failed to execute insmod");

        let _ = child.wait().expect("Child process wasn't running");
    }
}

fn unload_lime_module() {
    let mut child = Command::new("rmmod")
        .arg("lime")
        .spawn()
        .expect("Failed to execute rmmod");

    let _ = child.wait().expect("Child process wasn't running");
}

fn main() -> std::io::Result<()> {
    let (pid, virtual_address, length) = launcher();

    let virtual_address: u64 = match u64::from_str_radix(&virtual_address[2..], 16) {
        Ok(va) => va,
        Err(_) => {
            println!("Invalid virtual address");
            return Ok(());
        }
    };

    let maps_path = format!("/proc/{}/maps", pid);
    let pagemap_path = format!("/proc/{}/pagemap", pid);

    // Read the memory maps
    let file = File::open(maps_path)?;
    let reader = BufReader::new(file);
    let mut page_offset = 0;
    let mut found_mapping = false;
    let mut mapping_info = String::new();
    let mut physical_address = 0;
    for line in reader.lines() {
        let line = line?;
        let parts: Vec<&str> = line.split_whitespace().collect();

        if parts.len() < 6 {
            continue;
        }

        let address_range: Vec<&str> = parts[0].split('-').collect();

        if address_range.len() != 2 {
            continue;
        }

        let start_address: u64 = match u64::from_str_radix(address_range[0], 16) {
            Ok(va) => va,
            Err(_) => continue,
        };

        let end_address: u64 = match u64::from_str_radix(address_range[1], 16) {
            Ok(va) => va,
            Err(_) => continue,
        };

        if virtual_address >= start_address && virtual_address < end_address {
            // Correct page offset calculation
            page_offset = (virtual_address % PAGE_SIZE) as usize;
            found_mapping = true;

            // Store the mapping information
            mapping_info = format!(
                "{} {} {} {} {} {}",
                parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]
            );
            break;
        }
    }

    if !found_mapping {
        println!("Virtual address not found in process memory maps");
        return Ok(());
    }

    // Read the pagemap entry at the byte offset
    let file = File::open(pagemap_path)?;
    let mut reader = BufReader::new(file);
    let mut buffer = [0; 8];

    let page_index = virtual_address / PAGE_SIZE; // Get the page index
    let byte_offset = page_index * 8; // Each pagemap entry is 8 bytes long
    reader.seek(SeekFrom::Start(byte_offset))?;
    reader.read_exact(&mut buffer)?;

    let pagemap_entry = u64::from_le_bytes(buffer);
    let present = (pagemap_entry & (1 << 63)) != 0;
    let swapped = (pagemap_entry & (1 << 62)) != 0;

    if present {
        // PFN is contained in the lower 55 bits
        let pfn = pagemap_entry & 0x007FFFFFFFFFFFFF; // Mask out the lower 55 bits for the PFN

        // Correct physical address calculation
        physical_address = (pfn * PAGE_SIZE) + page_offset as u64;

        println!("Raw pagemap entry: 0x{:x}", pagemap_entry);
        println!("Raw PFN: 0x{:x}", pfn);
        println!("Page offset: {}", page_offset);
        println!("Mapping info: {}", mapping_info);
        println!("Physical address (hex): 0x{:x}", physical_address);
        println!("Physical address (dec): {}", physical_address);
    } else if swapped {
        let swap_type = (pagemap_entry & 0x1f) as u8; // Swap type in bits 0-4
        let swap_offset = (pagemap_entry >> 5) & 0x007FFFFFFFFFFFFF; // Swap offset

        println!(
            "Page is swapped, swap type: {}, swap offset: {}",
            swap_type, swap_offset
        );
    } else {
        println!("Page is not present in physical memory");
    }

    dump_raw_ram(LIME_MODULE.to_string(), MEMORY_FILE.to_string());

    let output = launch_xxd(physical_address, length, MEMORY_FILE.to_string());
    println!("Memory dump:");
    println!("{:?}", output);
    let message: libc::nlmsghdr = libc::nlmsghdr {
        nlmsg_len: u32::from_le_bytes(
            output[4..8]
                .try_into()
                .expect("Failed to convert bytes to array"),
        ),
        nlmsg_type: u16::from_le_bytes(
            output[8..10]
                .try_into()
                .expect("Failed to convert bytes to array"),
        ),
        nlmsg_flags: u16::from_le_bytes(
            output[10..12]
                .try_into()
                .expect("Failed to convert bytes to array"),
        ),
        nlmsg_seq: u32::from_le_bytes(
            output[12..16]
                .try_into()
                .expect("Failed to convert bytes to array"),
        ),
        nlmsg_pid: u32::from_le_bytes(
            output[16..20]
                .try_into()
                .expect("Failed to convert bytes to array"),
        ),
    };

    //Print ALL message fields
    println!("nlmsg_len: {}", message.nlmsg_len);
    println!("nlmsg_type: {}", message.nlmsg_type);
    println!("nlmsg_flags: {}", message.nlmsg_flags);
    println!("nlmsg_seq: {}", message.nlmsg_seq);
    println!("nlmsg_pid: {}", message.nlmsg_pid);

    unload_lime_module();

    Ok(())
}
