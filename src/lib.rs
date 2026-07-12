// Use mimalloc as the global allocator for significantly faster multi-threaded
// allocation throughput compared to the system allocator.
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

pub mod config;
pub mod packet;
#[cfg(target_os = "linux")]
pub mod raw_socket;
pub mod xor;
#[cfg(target_os = "linux")]
pub mod tunnel;
pub mod mux_fec;
pub mod quic;
#[cfg(target_os = "linux")]
pub mod app;
#[cfg(target_os = "linux")]
pub mod tun;
#[cfg(target_os = "linux")]
pub mod tun_bridge;
pub mod port_forward;
pub mod tuning;
pub mod logging;
pub mod check;
