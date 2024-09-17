extern crate ctrlc;
extern crate nftnl_sys;
extern crate nix;

use libc::{self, sockaddr_nl, NFPROTO_IPV4};
use nftnl_sys::*;
use nix::fcntl::{fcntl, FcntlArg, OFlag};
use std::ffi::CString;
use std::io::{self, ErrorKind, Write};
use std::marker::PhantomData;
use std::mem;
use std::os::raw::c_void;
use std::os::unix::io::RawFd;
use std::process::{exit, Command};
use std::sync::atomic::{AtomicBool, Ordering};
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

#[repr(C)]
struct Nla {
    nla_len: u16,
    nla_type: u16,
}

pub enum Verdict {
    NfAccept = 1, //NFQUEUE = 1
    NfDrop = 0,   //NFQUEUE = 0
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

        (*nlmsg).nlmsg_type = (NFTNL_EXPR_QUEUE_NUM as u16) | (queue_num as u16);

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

fn handle_queue(
    stdout: Arc<Mutex<io::Stdout>>,
    raw_fd: RawFd,
    queue_id: u32,
    running: Arc<AtomicBool>,
) {
    let mut buf = [0u8; 2048];

    while running.load(Ordering::SeqCst) {
        let size = unsafe { libc::recv(raw_fd, buf.as_mut_ptr() as *mut c_void, buf.len(), 0) };

        if size < 0 {
            let err = io::Error::last_os_error();
            if err.kind() != ErrorKind::WouldBlock {
                eprintln!("Error receiving packet: {}", err);
            }
            std::thread::sleep(std::time::Duration::from_millis(10)); // Small delay
            continue;
        }

        // Parse Netlink message header
        let nlmsg = buf.as_ptr() as *const libc::nlmsghdr;
        let nlmsg_type = unsafe { (*nlmsg).nlmsg_type };

        // Check if the message is NFQUEUE related
        if nlmsg_type == libc::NFNL_SUBSYS_QUEUE as u16 {
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

                // Handle the packet (accept it in this case)
                send_verdict(raw_fd, queue_id, packet_id, Verdict::NfAccept as u32)
                    .expect("Failed to send verdict");
            } else {
                eprintln!("Received message is smaller than expected NFQUEUE packet header size");
            }
        } else {
            // Ignore control messages like NLMSG_DONE or NLMSG_ERROR
            eprintln!(
                "Received non-NFQUEUE Netlink message of type: {}",
                nlmsg_type
            );
        }
    }
}

fn exit_program() {
    exit(1);
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

fn cleanup(rules: Vec<Arc<Mutex<SafePtr<nftnl_sys::nftnl_rule>>>>) {
    let _ = flush_nftables();
    unsafe {
        for rule in rules {
            nftnl_rule_free(rule.lock().unwrap().get());
        }
    }
}

fn allocate_ruleset(
    raw_fd: &Arc<Mutex<i32>>,
    table: &Arc<Mutex<SafePtr<nftnl_sys::nftnl_table>>>,
    chain: &Arc<Mutex<SafePtr<nftnl_sys::nftnl_chain>>>,
    rules: &mut Vec<Arc<Mutex<SafePtr<nftnl_sys::nftnl_rule>>>>,
) {
    for queue_num in 0..NFT_RULE_QUEUE_MAX_NUM {
        let rule = create_rule(&table, &chain, queue_num).expect("Failed to create rule");
        if rule.is_null() {
            eprintln!("Failed to create rule");
            cleanup(rules.clone());
            exit_program();
        }
        rules.push(Arc::new(Mutex::new(SafePtr::new(rule))));

        let mut buffer = vec![0u8; 1024]; // Allocate buffer for the Netlink message

        unsafe {
            let nlhdr = nftnl_nlmsg_build_hdr(
                buffer.as_mut_ptr() as *mut i8,
                NFTNL_CMD_ADD as u16,
                NFTNL_RULE_FAMILY as u16,
                0,
                queue_num,
            );
            nftnl_rule_nlmsg_build_payload(nlhdr, rule);

            send_to_kernel(*raw_fd.lock().unwrap(), &buffer);
        }
    }
}

fn bind_nfqueue_socket(sock_fd: RawFd) -> io::Result<()> {
    let mut addr: sockaddr_nl = unsafe { std::mem::zeroed() };
    addr.nl_family = libc::AF_NETLINK as u16;
    addr.nl_pid = 0;
    //let binary_representation = format!("{:b}", queue_index)
    //    .parse()
    //    .expect("Failed to convert string to u32");

    addr.nl_groups = 0;

    let ret = unsafe {
        libc::bind(
            sock_fd,
            &addr as *const _ as *const libc::sockaddr,
            mem::size_of::<libc::sockaddr_nl>() as u32,
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }

    let mut msg = libc::nlmsghdr {
        nlmsg_len: 0,
        nlmsg_type: libc::NFNL_SUBSYS_QUEUE as u16,
        nlmsg_flags: 0,
        nlmsg_seq: 0,
        nlmsg_pid: 0,
    };

    let mut attr = Nla {
        nla_len: 0,
        nla_type: 0,
    };

    let mut buf = [0u8; 1024];
    let mut offset = 0;

    // Set up the NFQUEUE protocol
    msg.nlmsg_len = mem::size_of::<libc::nlmsghdr>() as u32;
    msg.nlmsg_type = libc::NFNL_SUBSYS_QUEUE as u16;
    msg.nlmsg_flags = (libc::NLM_F_REQUEST | libc::NLM_F_CREATE) as u16;
    msg.nlmsg_seq = 0;
    msg.nlmsg_pid = 0;

    attr.nla_len = mem::size_of::<Nla>() as u16;
    attr.nla_type = libc::NFQA_CFG_QUEUE_MAXLEN as u16;

    let maxlen = 1024;
    let attr_data = &mut buf[offset..offset + attr.nla_len as usize];
    attr_data[0] = (maxlen >> 8) as u8;
    attr_data[1] = maxlen as u8;

    offset += attr.nla_len as usize;

    attr.nla_len = mem::size_of::<Nla>() as u16;
    attr.nla_type = libc::NFQA_CFG_FLAGS as u16;

    let flags = libc::NFQA_CFG_F_FAIL_OPEN | libc::NFQA_CFG_F_CONNTRACK;
    let attr_data = &mut buf[offset..offset + attr.nla_len as usize];
    attr_data[0] = (flags >> 8) as u8;
    attr_data[1] = flags as u8;

    //offset += attr.nla_len as usize;

    // Send the message
    let ret = unsafe {
        libc::send(
            sock_fd,
            &msg as *const _ as *const c_void,
            msg.nlmsg_len as usize,
            0,
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

fn create_nfqueue_socket() -> RawFd {
    let sock_fd =
        unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_NETFILTER) };
    if sock_fd < 0 {
        panic!(
            "Failed to create raw socket: {}",
            io::Error::last_os_error()
        );
    }
    sock_fd
}

fn send_to_kernel(sock: RawFd, buffer: &[u8]) {
    let ret = unsafe { libc::send(sock, buffer.as_ptr() as *const c_void, buffer.len(), 0) };
    if ret < 0 {
        eprintln!(
            "Error sending Netlink message: {}",
            io::Error::last_os_error()
        );
    }
}

//fn log_error(stdout: &Arc<Mutex<io::Stdout>>, message: &str) {
//    let mut stdout = stdout.lock().unwrap();
//    writeln!(stdout, "ERROR: {}", message).expect("Failed to write to stdout");
//}

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

    let raw_fd = Arc::new(Mutex::new(create_nfqueue_socket()));

    set_nonblocking(*raw_fd.lock().unwrap()).expect("Failed to set socket to non-blocking mode");

    allocate_ruleset(&raw_fd, &table_arc, &chain_arc, &mut *rules.lock().unwrap());

    let running = Arc::new(AtomicBool::new(true));

    let mut handles = Vec::new();
    for queue_id in 0..NFT_RULE_QUEUE_MAX_NUM {
        let raw_fd_thread = raw_fd.clone(); //fetching from one raw sockets. Until Bus speed is surpassed by internet speed.
        let _ = bind_nfqueue_socket(*raw_fd_thread.lock().unwrap());
        let stdout_clone = stdout.clone();
        let running = running.clone();
        let handle = thread::spawn(move || {
            handle_queue(
                stdout_clone,
                *raw_fd_thread.lock().unwrap(),
                queue_id,
                running,
            )
        });

        handles.push(handle);
    }
    {
        let running = running.clone();
        ctrlc::set_handler(move || {
            println!("Ctrl+C received, cleaning up...");
            cleanup(rules.lock().unwrap().clone());
            running.store(false, Ordering::SeqCst);
            // Free the chain, table, and ruleset safely
            unsafe {
                if !chain_arc.lock().unwrap().get().is_null() {
                    nftnl_chain_free(chain_arc.lock().unwrap().get());
                }

                if !table_arc.lock().unwrap().get().is_null() {
                    nftnl_table_free(table_arc.lock().unwrap().get());
                }
            }
            exit_program();
        })
        .expect("Error setting Ctrl+C handler");
    }

    // Wait for threads to finish
    for handle in handles {
        handle.join().unwrap();
    }
}
