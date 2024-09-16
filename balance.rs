extern crate ctrlc;
extern crate nftnl_sys;
extern crate nix;

use libc::{self, NFPROTO_IPV4};
use nftnl_sys::*;
use nix::fcntl::{fcntl, FcntlArg, OFlag};
use std::ffi::CString;
use std::io::{self, ErrorKind, Write};
use std::marker::PhantomData;
use std::mem;
use std::os::raw::c_void;
use std::os::unix::io::RawFd;
use std::process::{exit, Command};
use std::sync::{Arc, Mutex};
use std::thread;

// Constants for raw table configuration
const NFT_TABLE_NAME: &str = "raw";
const NFT_CHAIN_NAME: &str = "OUTPUT";
const NFT_RULE_QUEUE_MAX_NUM: u32 = 10;
const NFT_PROTOCOL_IP: u32 = libc::IPPROTO_IP as u32;

/// Wrapper around a raw pointer to manually implement Send and Sync.
struct SafePtr<T> {
    ptr: *mut T,
    _marker: PhantomData<T>,
}

unsafe impl<T> Send for SafePtr<T> {}
unsafe impl<T> Sync for SafePtr<T> {}

impl<T> SafePtr<T> {
    fn new(ptr: *mut T) -> Self {
        SafePtr {
            ptr,
            _marker: PhantomData,
        }
    }

    fn get(&self) -> *mut T {
        self.ptr
    }
}

#[repr(C)]
struct NfQueueMsg {
    id: u32,
    verdict: u32,
}

pub enum Verdict {
    NfAccept = 1,
    NfDrop = 0,
    NfStolen = 2,
    NfQueue = 3,
    NfRepeat = 4,
    NfStop = 5,
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

fn send_verdict(sock_fd: RawFd, queue_num: u32, packet_id: u32, verdict: u32) -> io::Result<()> {
    let nlmsg_size = mem::size_of::<libc::nlmsghdr>() + mem::size_of::<NfQueueMsg>();
    let mut buffer = vec![0u8; nlmsg_size];

    let nlmsg = buffer.as_mut_ptr() as *mut libc::nlmsghdr;

    unsafe {
        (*nlmsg).nlmsg_len = nlmsg_size as u32;
        (*nlmsg).nlmsg_type = libc::NFNL_SUBSYS_QUEUE as u16;
        (*nlmsg).nlmsg_flags = 0;
        (*nlmsg).nlmsg_seq = 0;
        (*nlmsg).nlmsg_pid = 0;

        let payload_ptr =
            (nlmsg as *mut u8).add(mem::size_of::<libc::nlmsghdr>()) as *mut NfQueueMsg;
        (*payload_ptr).id = packet_id;
        (*payload_ptr).verdict = verdict;

        (*nlmsg).nlmsg_type = (libc::NFNL_SUBSYS_QUEUE as u16) | (queue_num as u16);

        let ret = libc::send(sock_fd, nlmsg as *const c_void, nlmsg_size, 0);
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

fn create_rule(
    table: &Arc<Mutex<SafePtr<nftnl_sys::nftnl_table>>>,
    chain: &Arc<Mutex<SafePtr<nftnl_sys::nftnl_chain>>>,
    queue_num: u32,
) -> Option<*mut nftnl_rule> {
    let table = table.lock().unwrap().get();
    let chain = chain.lock().unwrap().get();
    unsafe {
        let rule = nftnl_rule_alloc();
        if rule.is_null() {
            eprintln!("Failed to allocate rule");
            return Some(std::ptr::null_mut());
        }

        nftnl_rule_set_u32(rule, NFTNL_RULE_FAMILY as u16, NFPROTO_IPV4 as u32);
        nftnl_rule_set(rule, NFTNL_RULE_TABLE as u16, table as *const c_void);
        nftnl_rule_set(rule, NFTNL_RULE_CHAIN as u16, chain as *const c_void);
        nftnl_rule_set_u32(rule, NFTNL_RULE_COMPAT_PROTO as u16, NFT_PROTOCOL_IP);

        let expr = nftnl_expr_alloc("queue\0".as_ptr() as *const i8);
        // Set the queue number using the provided constants
        nftnl_expr_set_u32(expr, NFTNL_EXPR_QUEUE_NUM as u16, queue_num);
        nftnl_rule_add_expr(rule, expr);

        Some(rule)
    }
}

fn create_table(table_name: *const i8) -> Option<*mut nftnl_table> {
    unsafe {
        let table = nftnl_table_alloc();
        if table.is_null() {
            eprintln!("Failed to allocate table");
            return None;
        }

        nftnl_table_set(
            table,
            nftnl_sys::NFTNL_TABLE_NAME as u16,
            table_name as *const c_void,
        );
        Some(table)
    }
}

fn create_chain(table: *mut nftnl_table, chain_name: *const i8) -> Option<*mut nftnl_chain> {
    unsafe {
        let chain = nftnl_chain_alloc();
        if chain.is_null() {
            eprintln!("Failed to allocate chain");
            return None;
        }

        nftnl_chain_set(
            chain,
            nftnl_sys::NFTNL_CHAIN_TABLE as u16,
            table as *const c_void,
        );
        nftnl_chain_set(
            chain,
            nftnl_sys::NFTNL_CHAIN_NAME as u16,
            chain_name as *const c_void,
        );
        Some(chain)
    }
}

fn handle_queue(stdout: Arc<Mutex<io::Stdout>>, raw_fd: RawFd, queue_id: u32) {
    let mut buf = [0u8; 2048];

    loop {
        let size = unsafe { libc::recv(raw_fd, buf.as_mut_ptr() as *mut c_void, buf.len(), 0) };

        if size < 0 {
            let err = io::Error::last_os_error();
            if err.kind() != ErrorKind::WouldBlock {
                eprintln!("Error receiving packet: {}", err);
            }
            std::thread::sleep(std::time::Duration::from_millis(10)); // Small delay
            continue;
        }

        let size = size as usize;
        let mut stdout = stdout.lock().unwrap();
        writeln!(stdout, "Received {} bytes", size).expect("Failed to write to stdout");

        for byte in &buf[..size] {
            print!("{:02x} ", byte);
        }
        println!();

        let nfq_packet_header_size =
            mem::size_of::<libc::nlmsghdr>() + mem::size_of::<NfQueueMsg>();
        if size >= nfq_packet_header_size {
            let nfq_msg_ptr = buf.as_ptr() as *const libc::nlmsghdr;
            let nfq_msg = unsafe { &*(nfq_msg_ptr as *const NfQueueMsg) };

            let packet_id = nfq_msg.id;

            send_verdict(raw_fd, queue_id, packet_id, Verdict::NfAccept as u32)
                .expect("Failed to send verdict");
        } else {
            eprintln!("Received message is smaller than expected NFQUEUE packet header size");
        }
    }
}

fn create_raw_ip_socket() -> RawFd {
    let sock_fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_RAW) };
    if sock_fd < 0 {
        panic!(
            "Failed to create raw socket: {}",
            io::Error::last_os_error()
        );
    }
    sock_fd
}

fn flush_nftables() -> Result<(), io::Error> {
    let output = Command::new("nft").args(&["flush", "ruleset"]).output()?;
    if output.status.success() {
        println!("Successfully flushed nftables rules");
        Ok(())
    } else {
        let error_message = String::from_utf8_lossy(&output.stderr);
        eprintln!("Failed to flush nftables rules: {}", error_message);
        Err(io::Error::new(io::ErrorKind::Other, error_message))
    }
}

fn exit_program() {
    exit(1);
}

fn cleanup(rules: Vec<Arc<Mutex<SafePtr<nftnl_sys::nftnl_rule>>>>) {
    let _ = flush_nftables();
    unsafe {
        for rule in rules {
            nftnl_rule_free(rule.lock().unwrap().get());
        }
    }
}

fn main() {
    let stdout = Arc::new(Mutex::new(io::stdout()));
    let table_name = CString::new(NFT_TABLE_NAME).unwrap();
    let chain_name = CString::new(NFT_CHAIN_NAME).unwrap();

    let table = SafePtr::new(create_table(table_name.as_ptr()).expect("Failed to create table"));
    let chain = SafePtr::new(
        create_chain(table.get(), chain_name.as_ptr()).expect("Failed to create chain"),
    );

    let table_arc = Arc::new(Mutex::new(table));
    let chain_arc = Arc::new(Mutex::new(chain));
    let rules = Arc::new(Mutex::new(Vec::new()));

    let raw_fd = Arc::new(Mutex::new(create_raw_ip_socket()));

    set_nonblocking(*raw_fd.lock().unwrap()).expect("Failed to set socket to non-blocking mode");

    let mut queue_threads = vec![];
    for queue_num in 0..NFT_RULE_QUEUE_MAX_NUM {
        let rule = create_rule(&table_arc, &chain_arc, queue_num).expect("Failed to create rule");
        if rule.is_null() {
            eprintln!("Failed to create rule");
            cleanup(rules.lock().unwrap().clone());
            exit_program();
        }
        rules
            .lock()
            .unwrap()
            .push(Arc::new(Mutex::new(SafePtr::new(rule))));

        let raw_fd = Arc::clone(&raw_fd);
        let stdout = Arc::clone(&stdout);
        let queue_thread = thread::spawn(move || {
            handle_queue(stdout, *raw_fd.lock().unwrap(), queue_num);
        });

        queue_threads.push(queue_thread);
    }

    ctrlc::set_handler(move || {
        println!("Ctrl+C received, cleaning up...");
        cleanup(rules.lock().unwrap().clone());
        exit_program();
    })
    .expect("Error setting Ctrl+C handler");

    for thread in queue_threads {
        thread.join().expect("Thread failed");
    }
}
