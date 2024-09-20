extern crate mnl_sys;
extern crate ctrlc;
extern crate nftnl_sys;
extern crate nix;

use libc::{self, getsockname, iovec, sockaddr_nl, socket, NFPROTO_IPV4};
use nftnl_sys::*;
use nix::fcntl::{fcntl, FcntlArg, OFlag};
use mnl_sys::*;
use std::ffi::CString;
use std::io::{self, Error, ErrorKind, Write};
use std::marker::PhantomData;
use std::mem;
use std::os::raw::c_void;
use std::os::unix::io::RawFd;
use std::process::{exit, Command};
use std::ptr::null_mut;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};
use std::borrow::BorrowMut;

// Constants for raw table configuration
const NFT_TABLE_NAME: &str = "raw_packets";
const NFT_CHAIN_NAME: &str = "output";
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
    struct Nla {
        nla_len: u16,
        nla_type: u16,
    }

#[repr(C, packed)]
struct NfQueueMsg {
    id: u32,
    verdict: u32,
}

pub struct NftnlBatch {
    batch_ptr: *mut nftnl_batch,
}

impl NftnlBatch {
    pub fn new(pg_size: u32, pg_overrun_size: u32) -> Self {
        let batch_ptr = unsafe { nftnl_batch_alloc(pg_size, pg_overrun_size) };
        if batch_ptr.is_null() {
            panic!("Failed to allocate nftnl_batch");
        }
        NftnlBatch { batch_ptr }
    }

    pub fn update(&mut self) -> Result<(), libc::c_int> {
        let result = unsafe { nftnl_batch_update(self.batch_ptr) };
        if result < 0 {
            return Err(result);
        }
        Ok(())
    }

    pub fn free(self) {
        unsafe {
            nftnl_batch_free(self.batch_ptr);
        }
    }

    pub fn buffer(&self) -> *mut c_void {
        unsafe { nftnl_batch_buffer(self.batch_ptr) }
    }

    pub fn buffer_len(&self) -> u32 {
        unsafe { nftnl_batch_buffer_len(self.batch_ptr) }
    }

    pub fn iovec_len(&self) -> libc::c_int {
        unsafe { nftnl_batch_iovec_len(self.batch_ptr) }
    }

    pub fn iovec(&self, iov: *mut libc::iovec, iovlen: u32) {
        unsafe { nftnl_batch_iovec(self.batch_ptr, iov, iovlen) }
    }

    pub fn begin(&mut self, buf: *mut libc::c_char, seq: u32) -> *mut libc::nlmsghdr {
        unsafe { nftnl_batch_begin(buf, seq) }
    }

    pub fn end(&mut self, buf: *mut libc::c_char, seq: u32) -> *mut libc::nlmsghdr {
        unsafe { nftnl_batch_end(buf, seq) }
    }
}



pub enum Verdict {
    NfAccept = 1, //NFQUEUE = 1
    NfDrop = 0,   //NFQUEUE = 0
    NfStolen = 2,
    NfQueue = 3,
    NfRepeat = 4,
    NfStop = 5,
}

fn handle_error(err_code: i32) -> &'static str {
    match err_code {
        libc::EACCES => "Permission denied (EACCES)",
        libc::EADDRINUSE => "Address already in use (EADDRINUSE)",
        libc::EADDRNOTAVAIL => "Address not available (EADDRNOTAVAIL)",
        libc::EAFNOSUPPORT => "Address family not supported (EAFNOSUPPORT)",
        libc::EAGAIN => "Resource temporarily unavailable (EAGAIN)",
        libc::EALREADY => "Connection already in progress (EALREADY)",
        libc::EBADF => "Bad file descriptor (EBADF)",
        libc::EBUSY => "Device or resource busy (EBUSY)",
        libc::ECONNABORTED => "Connection aborted (ECONNABORTED)",
        libc::ECONNREFUSED => "Connection refused (ECONNREFUSED)",
        libc::ECONNRESET => "Connection reset by peer (ECONNRESET)",
        libc::EDESTADDRREQ => "Destination address required (EDESTADDRREQ)",
        libc::EDQUOT => "Disk quota exceeded (EDQUOT)",
        libc::EEXIST => "File exists (EEXIST)",
        libc::EFAULT => "Bad address (EFAULT)",
        libc::EHOSTUNREACH => "No route to host (EHOSTUNREACH)",
        libc::EIDRM => "Identifier removed (EIDRM)",
        libc::EILSEQ => "Illegal byte sequence (EILSEQ)",
        libc::EINPROGRESS => "Operation in progress (EINPROGRESS)",
        libc::EINTR => "Interrupted system call (EINTR)",
        libc::EINVAL => "Invalid argument (EINVAL)",
        libc::EIO => "I/O error (EIO)",
        libc::EISCONN => "Socket is already connected (EISCONN)",
        libc::EISDIR => "Is a directory (EISDIR)",
        libc::ELOOP => "Too many levels of symbolic links (ELOOP)",
        libc::EMFILE => "Too many open files (EMFILE)",
        libc::EMLINK => "Too many links (EMLINK)",
        libc::EMSGSIZE => "Message too long (EMSGSIZE)",
        libc::ENAMETOOLONG => "File name too long (ENAMETOOLONG)",
        libc::ENETDOWN => "Network is down (ENETDOWN)",
        libc::ENETRESET => "Connection reset by network (ENETRESET)",
        libc::ENETUNREACH => "Network is unreachable (ENETUNREACH)",
        libc::ENFILE => "Too many open files in system (ENFILE)",
        libc::ENOBUFS => "No buffer space available (ENOBUFS)",
        libc::ENODEV => "No such device (ENODEV)",
        libc::ENOENT => "No such file or directory (ENOENT)",
        libc::ENOEXEC => "Exec format error (ENOEXEC)",
        libc::ENOLCK => "No locks available (ENOLCK)",
        libc::ENOMEM => "Out of memory (ENOMEM)",
        libc::ENOMSG => "No message of desired type (ENOMSG)",
        libc::ENOPROTOOPT => "Protocol not available (ENOPROTOOPT)",
        libc::ENOSPC => "No space left on device (ENOSPC)",
        libc::ENOSYS => "Function not implemented (ENOSYS)",
        libc::ENOTCONN => "Socket is not connected (ENOTCONN)",
        libc::ENOTDIR => "Not a directory (ENOTDIR)",
        libc::ENOTEMPTY => "Directory not empty (ENOTEMPTY)",
        libc::ENOTSOCK => "Socket operation on non-socket (ENOTSOCK)",
        libc::ENOTSUP => "Operation not supported (ENOTSUP)",
        libc::EPERM => "Operation not permitted (EPERM)",
        libc::EPIPE => "Broken pipe (EPIPE)",
        libc::EPROTO => "Protocol error (EPROTO)",
        libc::EPROTONOSUPPORT => "Protocol not supported (EPROTONOSUPPORT)",
        libc::EPROTOTYPE => "Protocol wrong type for socket (EPROTOTYPE)",
        libc::ERANGE => "Result too large (ERANGE)",
        libc::EROFS => "Read-only file system (EROFS)",
        libc::ESPIPE => "Invalid seek (ESPIPE)",
        libc::ESRCH => "No such process (ESRCH)",
        libc::ETIMEDOUT => "Connection timed out (ETIMEDOUT)",
        libc::ETXTBSY => "Text file busy (ETXTBSY)",
        libc::EWOULDBLOCK => "Operation would block (EWOULDBLOCK)",
        libc::EXDEV => "Cross-device link (EXDEV)",
        _ => "Unknown error",
    }
}

const NFNL_BUFFSIZE: usize = 4096;
const NFNL_MAX_SUBSYS: usize = 16;
const NFNL_F_SEQTRACK_ENABLED: u32 = 1 << 0;

// Define the callback struct (you may need to define this more fully based on your use case)
#[derive(Default)]
struct NfnlCallback {
    // Add relevant fields here for callback data
}

// Main struct definition
struct NfnlHandle {
    fd: RawFd,
    local: sockaddr_nl,
    peer: sockaddr_nl,
    subscriptions: u32,
    seq: u32,
    dump: u32,
    rcv_buffer_size: u32, // for nfnl_catch
    flags: u32,
    last_nlhdr: *mut libc::nlmsghdr, // Pointer to the last Netlink message header
    subsys: [NfnlSubsysHandle; NFNL_MAX_SUBSYS + 1], // Array of subsystem handles
}
impl Default for NfnlHandle {
    fn default() -> Self {
        NfnlHandle {
            fd: -1,
            local: unsafe { std::mem::zeroed() },
            peer: unsafe { std::mem::zeroed() },
            subscriptions: 0,
            seq: 0,
            dump: 0,
            rcv_buffer_size: NFNL_BUFFSIZE as u32,
            flags: 0,
            last_nlhdr: std::ptr::null_mut(),
            subsys: unsafe { std::mem::zeroed() },
        }
    }
}
#[derive(Clone, Copy)]
struct NfnlSubsysHandle {
    nfnlh: *mut NfnlHandle, // Pointer to nfnl_handle
    subscriptions: u32,     // Subscriptions bitmask
    subsys_id: u8,          // Subsystem ID
    cb_count: u8,           // Number of callbacks
    cb: *mut NfnlCallback,  // Array of callbacks (represented as a raw pointer)
}

impl NfnlSubsysHandle {
    fn new() -> Self {
        NfnlSubsysHandle {
            nfnlh: null_mut(), // Initialize pointer to null
            subscriptions: 0,
            subsys_id: 0,
            cb_count: 0,
            cb: null_mut(), // Initialize callback pointer to null
        }
    }
}

impl NfnlHandle {
    fn recalc_rebind_subscriptions(&mut self) {
        let mut new_subscriptions = self.subscriptions;

        // Combine subscriptions from all subsystems
        for i in 0..NFNL_MAX_SUBSYS {
            new_subscriptions |= self.subsys[i].subscriptions;
        }

        // Set the new subscription groups to the local sockaddr_nl
        self.local.nl_groups = new_subscriptions;

        // Bind the socket with the updated local address
        let local_addr = 
            // Create a reference to `sockaddr` using the pointer of `sockaddr_nl`
            &self.local as *const _ as *const libc::sockaddr;

        let ret = unsafe { 
            libc::bind(
                self.fd,
                local_addr,
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };

        if ret == -1 {
            // Retrieve the error code
            let errno = unsafe { *libc::__errno_location() };
            // Convert the error code to an io::Error
            let err = io::Error::from_raw_os_error(errno);
            eprintln!("Failed to bind socket on subscription: {}", err);
        }

        // Update the handle's subscriptions
        self.subscriptions = new_subscriptions;

    }

    fn new() -> Option<Self> {
        let mut nfnlh = NfnlHandle::default();
        unsafe {
            // Create socket
            let fd = create_netlink_socket();

            nfnlh.fd = fd;

            // Initialize sockaddr_nl structures
            nfnlh.local.nl_family = libc::AF_NETLINK as u16;
            nfnlh.peer.nl_family = libc::AF_NETLINK as u16;

            // Getsockname to verify socket configuration
            let mut addr_len = mem::size_of::<libc::sockaddr_nl>() as u32;
            if getsockname(
                fd,
                &mut nfnlh.local as *mut _ as *mut libc::sockaddr,
                &mut addr_len as *mut _,
            ) < 0
                || addr_len != mem::size_of::<libc::sockaddr_nl>() as u32
            {
                libc::close(fd);

                return None;
            }

            if nfnlh.local.nl_family != libc::AF_NETLINK as u16 {
                libc::close(fd);

                return None;
            }

            // Set sequence number
            nfnlh.seq = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as u32;

            // Set receive buffer size
            nfnlh.rcv_buffer_size = NFNL_BUFFSIZE as u32;

            nfnlh.recalc_rebind_subscriptions();

            // Final getsockname to get the netlink PID
            if getsockname(
                fd,
                &mut nfnlh.local as *mut _ as *mut libc::sockaddr,
                &mut addr_len as *mut _,
            ) < 0
                || addr_len != mem::size_of::<libc::sockaddr_nl>() as u32
            {
                libc::close(fd);
                return None;
            }

            // Enable sequence tracking
            nfnlh.flags |= NFNL_F_SEQTRACK_ENABLED;

            Some(nfnlh)
        }
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

fn validate_table_netlink_response(handler: &mut NfnlHandle, recv_buffer: &[u8], recv_len: usize) -> bool {
    if recv_len < std::mem::size_of::<libc::nlmsghdr>() {
        eprintln!("Received response is too short to be valid");
        return false;
    }

    // Get the pointer to the first netlink message header
    let nlh: *const libc::nlmsghdr = recv_buffer.as_ptr() as *const libc::nlmsghdr;

    // Allocate a new table to parse the response into
    unsafe {
        let parsed_table = nftnl_table_alloc();
        if parsed_table.is_null() {
            eprintln!("Failed to allocate memory for parsed table");
            return false;
        }

        // Parse the netlink message
        handler.last_nlhdr = nlh as *mut libc::nlmsghdr;
        let ret: i32 = nftnl_table_nlmsg_parse(nlh as *const libc::nlmsghdr, parsed_table);
        if ret < 0 {
            eprintln!("Failed to parse netlink message, error code: {}", ret);
            nftnl_table_free(parsed_table);
            return false;
        }

        let nlmsg_type =  (*nlh).nlmsg_type;
        let nlmsg_flags = (*nlh).nlmsg_flags;

        // Check if the message type indicates an error
        if nlmsg_type == libc::NLMSG_ERROR as u16 {
            // Extract the error code from the message
            let error = (*(recv_buffer.as_ptr() as *const libc::nlmsgerr)).error;
            eprintln!("Received error from kernel: {}", handle_error(error));
            return false;
        }

        // Optionally check for other flags, like acknowledgment
        if nlmsg_flags & libc::NLM_F_ACK as u16 != 0 {
            println!("Received acknowledgment from kernel");
        }
        nftnl_table_free(parsed_table);
    }

    // Assuming successful parsing means the table was created
    println!("Table creation was successful");
    true
}

fn validate_chain_netlink_response(handler: &NfnlHandle, recv_buffer: &[u8], recv_len: usize) -> bool {
    if recv_len < std::mem::size_of::<libc::nlmsghdr>() {
        eprintln!("Received response is too short to be valid");
        return false;
    }

    // Get the pointer to the first netlink message header
    //let nlh: *const libc::nlmsghdr = recv_buffer.as_ptr() as *const libc::nlmsghdr;

    // Allocate a new table to parse the response into
    unsafe {
        let parsed_chain = nftnl_chain_alloc();
        if parsed_chain.is_null() {
            eprintln!("Failed to allocate memory for parsed chain");
            return false;
        }

        // Parse the netlink message
        let last_nlhdr = handler.last_nlhdr;
        let ret: i32 = nftnl_chain_nlmsg_parse(last_nlhdr as *const libc::nlmsghdr, parsed_chain);
        if ret < 0 {
            eprintln!("Failed to parse netlink message, error code: {}", ret);
            nftnl_chain_free(parsed_chain);
            return false;
        }

        let nlmsg_type = (*last_nlhdr).nlmsg_type;
        let nlmsg_flags = (*last_nlhdr).nlmsg_flags;

        // Check if the message type indicates an error
        if nlmsg_type == libc::NLMSG_ERROR as u16 {
            // Extract the error code from the message
            let error = (*(recv_buffer.as_ptr() as *const libc::nlmsgerr)).error;
            eprintln!("Received error from kernel: {}", handle_error(error));
            return false;
        }

        // Optionally check for other flags, like acknowledgment
        if nlmsg_flags & libc::NLM_F_ACK as u16 != 0 {
            println!("Received acknowledgment from kernel");
        }
        // Clean up the parsed table object
        nftnl_chain_free(parsed_chain);
    }

    // Assuming successful parsing means the table was created
    println!("Chain creation was successful");
    true
}

fn validate_rule_netlink_response(recv_buffer: &[u8], recv_len: usize) -> bool {
    if recv_len < std::mem::size_of::<libc::nlmsghdr>() {
        eprintln!("Received response is too short to be valid");
        return false;
    }

    // Get the pointer to the first netlink message header
    let nlh: *const libc::nlmsghdr = recv_buffer.as_ptr() as *const libc::nlmsghdr;

    // Allocate a new table to parse the response into
    unsafe {
        let parsed_rule = nftnl_rule_alloc();
        if parsed_rule.is_null() {
            eprintln!("Failed to allocate memory for parsed rule");
            return false;
        }

        // Parse the netlink message
        let ret: i32 = nftnl_rule_nlmsg_parse(nlh, parsed_rule);
        if ret < 0 {
            eprintln!("Failed to parse netlink message, error code: {}", ret);
            nftnl_rule_free(parsed_rule);
            return false;
        }

        let nlmsg_type = (*nlh).nlmsg_type;
        let nlmsg_flags = (*nlh).nlmsg_flags;

        // Check if the message type indicates an error
        if nlmsg_type == libc::NLMSG_ERROR as u16 {
            // Extract the error code from the message
            let error = (*(recv_buffer.as_ptr() as *const libc::nlmsgerr)).error;
            eprintln!("Received error from kernel: {}", handle_error(error));
            return false;
        }

        // Optionally check for other flags, like acknowledgment
        if nlmsg_flags & libc::NLM_F_ACK as u16 != 0 {
            println!("Received acknowledgment from kernel");
        }

        // Clean up the parsed table object
        nftnl_rule_free(parsed_rule);
    }

    // Assuming successful parsing means the table was created
    println!("Rule creation was successful");
    true
}

fn convert_nlmsghdr_to_msghdr(buffer: &mut [i8], originalnlh: *mut libc::nlmsghdr, table_name: &str) -> libc::msghdr {
    let mut batch = NftnlBatch::new(4096, 1024);

    // Prepare sockaddr_nl
    let mut addr: sockaddr_nl = unsafe { mem::zeroed() };
    addr.nl_family = libc::AF_NETLINK as u16; // Set to AF_NETLINK
    addr.nl_pid = unsafe{ (*originalnlh).nlmsg_pid}; // to follow with the handler.
    addr.nl_groups = 0; // No multicast groups

    // Begin the batch
    let nlh = batch.begin(buffer.as_mut_ptr() as *mut i8, 0);

    // Construct the batch begin message
    let nlh_begin = unsafe { &mut *(nlh as *mut libc::nlmsghdr) };
    nlh_begin.nlmsg_len = (mem::size_of::<libc::nlmsghdr>()) as u32; // Length of the header
    nlh_begin.nlmsg_type = libc::NFNL_MSG_BATCH_BEGIN as u16;
    nlh_begin.nlmsg_flags = libc::NLM_F_REQUEST as u16;
    nlh_begin.nlmsg_seq = 0; // Sequence number
    nlh_begin.nlmsg_pid = addr.nl_pid; // Kernel

    // Construct the new table message
    let nlh_new_table = unsafe { &mut *(nlh.add(nlh_begin.nlmsg_len as usize) as *mut libc::nlmsghdr) };
    let table_name_length = table_name.len();
    let total_length = mem::size_of::<libc::nlmsghdr>() + 8 + (mem::size_of::<Nla>() + table_name_length + 1) + 8; // Adjusted for the expected structure

    nlh_new_table.nlmsg_len = total_length as u32; // Total length
    nlh_new_table.nlmsg_type = ((libc::NFNL_SUBSYS_NFTABLES << 8) | libc::NFT_MSG_NEWTABLE) as u16;
    nlh_new_table.nlmsg_flags = libc::NLM_F_REQUEST as u16;
    nlh_new_table.nlmsg_seq = 1; // Sequence number
    nlh_new_table.nlmsg_pid = addr.nl_pid; // Kernel

    // Construct the nfgen family and version
    let nfgen_family_offset = mem::size_of::<libc::nlmsghdr>();
    let nfgen_family_msg = unsafe { (nlh_new_table as *mut libc::nlmsghdr as *mut u8).add(nfgen_family_offset) as *mut u8 };
    unsafe {
        // Set nfgen_family and version
        *(nfgen_family_msg as *mut u16) = libc::AF_INET as u16; // Set to AF_INET
        *(nfgen_family_msg.add(2) as *mut u8) = 0x61; // Set version to NFNETLINK_V0
        *(nfgen_family_msg.add(3) as *mut u8) = 0; // Reserved
        *(nfgen_family_msg.add(4) as *mut u16) = 0; // res_id
    }

    // Construct the Nla for table_name
    let nla_offset = nfgen_family_offset + 8; // Offset for nfgen family
    let nla = unsafe { (nlh_new_table as *mut libc::nlmsghdr as *mut u8).add(nla_offset) as *mut Nla };

    // Set the Nla for table_name
    unsafe {
        (*nla).nla_len = (mem::size_of::<Nla>() + table_name_length + 1) as u16; // Length of the attribute
        (*nla).nla_type = 0x2; // Type of the attribute
    
    println!("####NLA Length: {}", (*nla).nla_len); // Debug print
    }

    // Copy the table name into the Nla
    let table_name_msg = unsafe { (nla as *mut u8).add(mem::size_of::<Nla>()) as *mut u8 };
    for i in 0..table_name_length {
        unsafe { *table_name_msg.offset(i as isize) = table_name.as_bytes()[i] };
    }
    unsafe { *table_name_msg.offset(table_name_length as isize) = 0 }; // Null-terminate the string
    
    // Set the second nested attribute (8 bytes of zero)
    let second_nla_offset = nla_offset + mem::size_of::<Nla>() + table_name_length + 1;
    let second_nla = unsafe { (nlh_new_table as *mut libc::nlmsghdr as *mut u8).add(second_nla_offset) as *mut u8 };
    unsafe {
        for i in 0..8 {
            *second_nla.offset(i) = 0; // Fill with zeros
        }
    }

    // Construct the batch end message
    let nlh_end = unsafe { &mut *(nlh.add(nlh_begin.nlmsg_len as usize + nlh_new_table.nlmsg_len as usize) as *mut libc::nlmsghdr) };
    nlh_end.nlmsg_len = (mem::size_of::<libc::nlmsghdr>()) as u32; // Length of the header
    nlh_end.nlmsg_type = libc::NFNL_MSG_BATCH_END as u16;
    nlh_end.nlmsg_flags = libc::NLM_F_REQUEST as u16;
    nlh_end.nlmsg_seq = 2; // Sequence number
    nlh_end.nlmsg_pid = addr.nl_pid; // Kernel

    // Update the batch buffer
    unsafe { nftnl_batch_update(batch.batch_ptr) };

    // Prepare the msghdr structure
    let mut msgh: libc::msghdr = unsafe { mem::zeroed() };
    msgh.msg_name = &addr as *const _ as *mut c_void; // Correctly set msg_name
    msgh.msg_namelen = mem::size_of::<sockaddr_nl>() as u32;

    // Prepare the iovec array
    let mut iov: [libc::iovec; 3] = unsafe { mem::zeroed() }; // Array for 3 messages

    // Populate the iovec array
    iov[0] = libc::iovec {
        iov_base: nlh as *mut c_void, // Pointer to the batch begin message
        iov_len: nlh_begin.nlmsg_len as usize,
    };
    iov[1] = libc::iovec {
        iov_base: nlh_new_table as *mut libc::nlmsghdr as *mut c_void, // Pointer to the new table message
        iov_len: nlh_new_table.nlmsg_len as usize,
    };
    iov[2] = libc::iovec {
        iov_base: nlh_end as *mut libc::nlmsghdr as *mut c_void, // Pointer to the batch end message
        iov_len: nlh_end.nlmsg_len as usize,
    };

    msgh.msg_iov = iov.as_mut_ptr(); // Pointer to the iovec array
    msgh.msg_iovlen = iov.len() as usize; // Number of iovec entries
    msgh.msg_control = std::ptr::null_mut(); // No control messages
    msgh.msg_controllen = 0; // No ancillary data
    msgh.msg_flags = 0;

    let msgh_clone = msgh.clone();

    // Free the batch when done
    batch.free();

    msgh_clone // Return the populated msghdr
}






fn create_table(table_name: CString) -> (Option<*mut nftnl_table>, NfnlHandle) {
    let mut buffer = [0i8; NFNL_BUFFSIZE]; // Allocate buffer for the Netlink message
    unsafe {
        
        match NfnlHandle::new() {
            Some(mut handler) => {
                // Allocate a new table
                let table = nftnl_table_alloc();
                if table.is_null() {
                    eprintln!("Failed to allocate table");
                    return (None, handler);
                }
                
                println!("nfnetlink handler created successfully!");
                nftnl_table_set_str(table, NFTNL_TABLE_NAME as u16, table_name.as_ptr());
                nftnl_table_set_u32(table, NFTNL_TABLE_FAMILY as u16, NFPROTO_IPV4 as u32);
                //nftnl_table_set_u32(table, NFTNL_TABLE_FLAGS as u16, 0u32);
                //nftnl_table_set_u32(table, NFTNL_TABLE_USE as u16, 0u32);
                //nftnl_table_set_u64(table, NFTNL_TABLE_HANDLE as u16, handler.subscriptions as u64);

                handler.last_nlhdr = nftnl_nlmsg_build_hdr(
                    buffer.as_mut_ptr(),
                    libc::NFT_MSG_NEWTABLE as u16,
                    libc::AF_NETLINK as u16,
                    libc::NLM_F_REQUEST as u16, //| libc::NLM_F_CREATE) as u16, //| libc::NLM_F_ACK) as u16,
                    handler.seq + 1,
                );

                // Add tableNFNL_BUFFSIZE
                let nlh = handler.last_nlhdr;
                (*nlh).nlmsg_pid = handler.local.nl_pid;

                nftnl_table_nlmsg_build_payload(nlh, table);

                // Bind the socket
                //let _ = bind_nfqueue_socket(sock_fd, 0);

                //println!("{:#?}", &buffer[0..100]);

                let msg = convert_nlmsghdr_to_msghdr(&mut buffer, nlh, table_name.to_str().unwrap());


                if let Err(err) = send_msg_kernel(handler.fd, &msg) {
                    eprintln!("Failed to send TABLE: {}", err);
                    nftnl_table_free(table);
                    exit_program();
                }

                // Receive the response from the kernel
                let mut recv_buffer = vec![0u8; NFNL_BUFFSIZE]; // Allocate a buffer for the response
                let mut addr: libc::sockaddr_nl = std::mem::zeroed(); // Address structure for recvfrom
                let mut addrlen = std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t;

                let recv_len = libc::recvfrom(
                    handler.fd,
                    recv_buffer.as_mut_ptr() as *mut libc::c_void,
                    recv_buffer.len(),
                    0,
                    &mut addr as *mut _ as *mut libc::sockaddr,
                    &mut addrlen,
                );

                if recv_len < 0 {
                    eprintln!("Failed to receive response from kernel");
                    nftnl_table_free(table);
                    libc::close(handler.fd);
                    return (None, handler);
                }

                // Here you would process the response to ensure success.
                // Example of response validation (Netlink message processing)
                if validate_table_netlink_response(handler.borrow_mut(), &recv_buffer, recv_len as usize) {
                    println!("Table successfully created");
                } else {
                    nftnl_table_free(table);
                    libc::close(handler.fd);
                    return (None, handler);
                }

                //libc::close(handler.fd); //TODO PASS THAT TO THE NEXT FUNCTION && close the handler at the END!
                return (Some(table), handler);
            
            }
            None => {
                eprintln!("Failed to create nfnetlink handler.");
                return (None, NfnlHandle::default());
            }
        }
    }
}

fn create_chain(mut handler: NfnlHandle, table: *mut nftnl_table, chain_name: *const i8) -> (Option<*mut nftnl_chain>, NfnlHandle) {
    let mut buffer = vec![0u8; NFNL_BUFFSIZE]; // Allocate buffer for the Netlink message
    unsafe {
        let chain = nftnl_chain_alloc();
        if chain.is_null() {
            eprintln!("Failed to allocate chain");
            return (None, handler);
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

        handler.last_nlhdr = nftnl_nlmsg_build_hdr(
            buffer.as_mut_ptr() as *mut i8,
            libc::NLMSG_DONE as u16,
            libc::AF_NETLINK as u16,
            (libc::NLM_F_REQUEST | libc::NLM_F_CREATE | libc::NFT_MSG_NEWCHAIN | libc::NLM_F_ACK)
                as u16,
            0,
        );

        // add chain
        nftnl_chain_nlmsg_build_payload(handler.last_nlhdr, chain);

        // Bind the socket
        //let _ = bind_nfqueue_socket(handler.fd, 0);

        if let Err(err) = send_to_kernel(handler.fd, &buffer) {
            eprintln!("Failed to send CHAIN: {}", err);
            nftnl_chain_free(chain);
            exit_program();
        }

        // Receive the response from the kernel
        let mut recv_buffer = vec![0u8; NFNL_BUFFSIZE]; // Allocate a buffer for the response
        let mut addr: libc::sockaddr_nl = std::mem::zeroed(); // Address structure for recvfrom
        let mut addrlen = std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t;

        let recv_len = libc::recvfrom(
            handler.fd,
            recv_buffer.as_mut_ptr() as *mut libc::c_void,
            recv_buffer.len(),
            0,
            &mut addr as *mut _ as *mut libc::sockaddr,
            &mut addrlen,
        );

        if recv_len < 0 {
            eprintln!("Failed to receive response from kernel");
            nftnl_chain_free(chain);
            libc::close(handler.fd);
            return (None, handler);
        }

        // Here you would process the response to ensure success.
        // Example of response validation (Netlink message processing)
        if validate_chain_netlink_response(&handler, &recv_buffer, recv_len as usize) {
            println!("Chain successfully created");
        } else {
            nftnl_chain_free(chain);
            libc::close(handler.fd);
            return (None, handler);
        }

        //libc::close(sock_fd);
        return (Some(chain), handler);
    }
}

fn create_rule(
    raw_fd: RawFd, //handler.fd
    table: &Arc<Mutex<SafePtr<nftnl_sys::nftnl_table>>>,
    chain: &Arc<Mutex<SafePtr<nftnl_sys::nftnl_chain>>>,
    queue_num: u32,
) -> Option<*mut nftnl_rule> {
    let table = table.lock().unwrap().get();
    let chain = chain.lock().unwrap().get();
    let mut buffer = vec![0u8; NFNL_BUFFSIZE]; // Allocate buffer for the Netlink message
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

        let queue_expr = nftnl_expr_alloc("queue\0".as_ptr() as *const i8);
        if queue_expr.is_null() {
            eprintln!("Failed to allocate queue expression");
            nftnl_rule_free(rule);
        }
        // Set the queue number using the provided constants
        nftnl_expr_set_u32(queue_expr, NFTNL_EXPR_QUEUE_NUM as u16, queue_num);
        nftnl_rule_add_expr(rule, queue_expr);

        // add rule
        let nlhdr = nftnl_nlmsg_build_hdr(
            buffer.as_mut_ptr() as *mut i8,
            libc::NLMSG_DONE as u16,
            libc::AF_NETLINK as u16,
            (libc::NLM_F_REQUEST | libc::NLM_F_CREATE | libc::NFT_MSG_NEWRULE | libc::NLM_F_ACK)
                as u16,
            queue_num,
        );

        nftnl_rule_nlmsg_build_payload(nlhdr, rule);

        if let Err(err) = send_to_kernel(raw_fd, &buffer) {
            eprintln!("Failed to send RULE for queue {}: {}", queue_num, err);
            nftnl_rule_free(rule);
            exit_program();
        }

        // Receive the response from the kernel
        let mut recv_buffer = vec![0u8; NFNL_BUFFSIZE]; // Allocate a buffer for the response
        let mut addr: libc::sockaddr_nl = std::mem::zeroed(); // Address structure for recvfrom
        let mut addrlen = std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t;

        let recv_len = libc::recvfrom(
            raw_fd,
            recv_buffer.as_mut_ptr() as *mut libc::c_void,
            recv_buffer.len(),
            0,
            &mut addr as *mut _ as *mut libc::sockaddr,
            &mut addrlen,
        );

        if recv_len < 0 {
            eprintln!("Failed to receive response from kernel");
            nftnl_rule_free(rule);
            libc::close(raw_fd);
            return None;
        }

        // Here you would process the response to ensure success.
        // Example of response validation (Netlink message processing)
        if validate_rule_netlink_response(&recv_buffer, recv_len as usize) {
            println!("Rule successfully created");
        } else {
            nftnl_rule_free(rule);
            libc::close(raw_fd);
            return None;
        }

        Some(rule)
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

fn exit_program() -> ! {
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
    handler: &NfnlHandle,
    table: &Arc<Mutex<SafePtr<nftnl_sys::nftnl_table>>>,
    chain: &Arc<Mutex<SafePtr<nftnl_sys::nftnl_chain>>>,
    rules: &mut Vec<Arc<Mutex<SafePtr<nftnl_sys::nftnl_rule>>>>,
) -> Vec<Arc<Mutex<i32>>> {
    let mut raw_fds: Vec<Arc<Mutex<i32>>> = Vec::new();
    for queue_num in 0..NFT_RULE_QUEUE_MAX_NUM {
        raw_fds.push(Arc::new(Mutex::new(create_netlink_socket())));

        let raw_fd = raw_fds.last().unwrap().clone();

        set_nonblocking(*raw_fd.lock().unwrap())
            .expect("Failed to set socket to non-blocking mode");

        // Bind the socket to the queue number
        if bind_nfqueue_socket(*raw_fd.lock().unwrap(), queue_num).is_err() {
            continue; // Skip to the next queue if binding fails
        }

        let rule = match create_rule(handler.fd, &table, &chain, queue_num) {
            Some(r) => r,
            None => {
                eprintln!("Failed to create rule for queue {}", queue_num);
                cleanup(rules.clone());
                exit_program();
            }
        };

        rules.push(Arc::new(Mutex::new(SafePtr::new(rule))));
    }
    raw_fds
}

fn socket_exists(sock_fd: RawFd) -> bool {
    if sock_fd < 0 {
        return false; // File descriptor is invalid
    }

    // Use fcntl to check if the file descriptor is valid
    let ret = fcntl(sock_fd, FcntlArg::F_GETFL).unwrap_or(-1);
    ret != -1 // If ret is -1, the file descriptor is not valid
}

fn bind_nfqueue_socket(sock_fd: RawFd, queue_id: u32) -> io::Result<()> {
    if !socket_exists(sock_fd) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Socket file descriptor does not exist",
        ));
    }

    let mut addr: sockaddr_nl = unsafe { std::mem::zeroed() };
    addr.nl_family = libc::AF_NETLINK as u16;
    addr.nl_pid = 0;
    // Create a bitmask for the specified queue_id
    let mask: u32 = (1 << queue_id) as u32;

    // Set nl_groups to the mask
    addr.nl_groups = mask;

    // Set socket option for reusability
    unsafe {
        let option_value: libc::c_int = 1;
        let result = libc::setsockopt(
            sock_fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            &option_value as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
    }

    // Attempt to bind the socket
    let ret = unsafe {
        libc::bind(
            sock_fd,
            &addr as *const _ as *const libc::sockaddr,
            mem::size_of::<sockaddr_nl>() as u32,
        )
    };
    if ret < 0 {
        let error_code = io::Error::last_os_error();
        eprintln!("Failed to bind to queue {}: {}", queue_id, error_code);
        // Check the error code
        match error_code.kind() {
            io::ErrorKind::AddrInUse => {
                eprintln!("Address already in use");
            }
            io::ErrorKind::PermissionDenied => {
                eprintln!("Permission denied");
            }
            io::ErrorKind::InvalidInput => {
                eprintln!("Invalid input");
            }
            _ => {
                eprintln!("Unknown error");
            }
        }
        return Err(error_code);
    }
    Ok(())
}

fn create_netlink_socket() -> i32 {
    let sock_fd =
        unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_NETFILTER) };
    if sock_fd < 0 {
        return -1;
    }
    sock_fd
}

fn send_to_kernel(sock: RawFd, buffer: &[u8]) -> Result<(), Error> {
    let ret = unsafe { libc::send(sock, buffer.as_ptr() as *const c_void, buffer.len(), 0) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn send_msg_kernel(sock: RawFd, msghdr: *const libc::msghdr) -> Result<(), Error> {
    let ret = unsafe { libc::sendmsg(sock, msghdr,0) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

//fn log_error(stdout: &Arc<Mutex<io::Stdout>>, message: &str) {
//    let mut stdout = stdout.lock().unwrap();
//    writeln!(stdout, "ERROR: {}", message).expect("Failed to write to stdout");
//}

fn main() {
    let stdout = Arc::new(Mutex::new(io::stdout()));
    let table_name = CString::new(NFT_TABLE_NAME).unwrap();
    let chain_name = CString::new(NFT_CHAIN_NAME).unwrap();

    // Create table
    let (table, handler) = match create_table(table_name) {
        (Some(t), handler) => (SafePtr::new(t), handler),
        (None, _handler) => {
            eprintln!("Failed to create table");
            exit_program();
        }
    };

    // Create chain
    let (chain, handler) = match create_chain(handler, table.get(), chain_name.as_ptr()) {
        (Some(c), handler) => (SafePtr::new(c), handler),
        (None, _handler) => {
            eprintln!("Failed to create chain");
            exit_program();
        }
    };

    let table_arc = Arc::new(Mutex::new(table));
    let chain_arc = Arc::new(Mutex::new(chain));

    let rules = Arc::new(Mutex::new(Vec::new()));

    let raw_fds = allocate_ruleset(&handler, &table_arc, &chain_arc, &mut *rules.lock().unwrap());

    let running = Arc::new(AtomicBool::new(true));

    let mut handles = Vec::new();
    for queue_id in 0..NFT_RULE_QUEUE_MAX_NUM {
        let raw_fd_thread = Arc::clone(&raw_fds[queue_id as usize]);
        let stdout_clone = stdout.clone();
        let running_clone = Arc::clone(&running);

        // Spawn a thread for handling packets on this queue
        let handle = thread::spawn({;
            move || {
                handle_queue(
                    stdout_clone,
                    *raw_fd_thread.lock().unwrap(),
                    queue_id,
                    Arc::clone(&running_clone),
                );
            }
        });

        handles.push(handle);
    }

    // Ctrl+C signal handling
    {
        let running = running.clone();
        ctrlc::set_handler(move || {
            println!("Ctrl+C received, cleaning up...");
            cleanup(rules.lock().unwrap().clone());
            running.store(false, Ordering::SeqCst);
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

    // Wait for all threads to finish
    for handle in handles {
        if let Err(e) = handle.join() {
            eprintln!("Thread encountered an error: {:?}", e);
        }
    }
}
