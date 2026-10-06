use adg_xdp_common::{HostStats, ExtendedHostStats, TrustEntry};
use anyhow::Context as _;
use aya::{
    maps::HashMap,
    programs::{Xdp, XdpFlags},
};
use clap::Parser;
#[rustfmt::skip]
use log::{debug, warn};
use std::{collections, net::Ipv4Addr, sync::Arc, sync::atomic::{AtomicU64, Ordering}, time::Duration};
use tokio::{signal, sync::RwLock};


#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "enp1s0")]
    iface: String,
}

mod profiler;
mod telemetry_extensions;
mod trust;
mod network_intelligence;

use profiler::HostProfiler;
use trust::TrustEngine;

fn get_ktime_ns() -> u64 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    unsafe {
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts);
    }
    (ts.tv_sec as u64) * 1_000_000_000 + (ts.tv_nsec as u64)
}

/// Compute the delta between the current and previous HostStats snapshots.
/// This gives us a windowed view of activity over the last polling interval,
/// rather than cumulative all-time counters.
fn compute_delta(current: &HostStats, previous: &HostStats) -> HostStats {
    HostStats {
        packets: current.packets.saturating_sub(previous.packets),
        bytes: current.bytes.saturating_sub(previous.bytes),
        tcp_packets: current.tcp_packets.saturating_sub(previous.tcp_packets),
        udp_packets: current.udp_packets.saturating_sub(previous.udp_packets),
        icmp_packets: current.icmp_packets.saturating_sub(previous.icmp_packets),
        syn_packets: current.syn_packets.saturating_sub(previous.syn_packets),
        frag_packets: current.frag_packets.saturating_sub(previous.frag_packets),
        // Preserve last_seen from the current reading so idle detection works correctly
        last_seen: current.last_seen,
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/adg-xdp"
    )))?;
    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }

    let Opt { iface } = opt;
    let program: &mut Xdp = ebpf.program_mut("adg_xdp").unwrap().try_into()?;
    program.load()?;
    program.attach(&iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    let host_stats: HashMap<_, u32, HostStats> =
        HashMap::try_from(ebpf.take_map("HOST_STATS").ok_or_else(|| anyhow::anyhow!("HOST_STATS map not found"))?)?;

    let host_trust_map = ebpf.take_map("HOST_TRUST").ok_or_else(|| anyhow::anyhow!("HOST_TRUST map not found"))?;
    let pin_path = "/sys/fs/bpf/HOST_TRUST";
    if std::path::Path::new(pin_path).exists() {
        let _ = std::fs::remove_file(pin_path);
    }
    host_trust_map.pin(pin_path).context("Failed to pin HOST_TRUST map")?;
    let mut host_trust: HashMap<_, u32, TrustEntry> = HashMap::try_from(host_trust_map)?;

    let ext_stats_map = ebpf.take_map("EXTENDED_HOST_STATS").ok_or_else(|| anyhow::anyhow!("EXTENDED_HOST_STATS map not found"))?;
    let ext_pin_path = "/sys/fs/bpf/EXTENDED_HOST_STATS";
    if std::path::Path::new(ext_pin_path).exists() {
        let _ = std::fs::remove_file(ext_pin_path);
    }
    ext_stats_map.pin(ext_pin_path).context("Failed to pin EXTENDED_HOST_STATS map")?;
    let _ext_stats_bpf: HashMap<_, u32, ExtendedHostStats> = HashMap::try_from(ext_stats_map)?;

    let host_risk_map = ebpf.take_map("HOST_RISK").ok_or_else(|| anyhow::anyhow!("HOST_RISK map not found"))?;
    let risk_pin_path = "/sys/fs/bpf/HOST_RISK";
    if std::path::Path::new(risk_pin_path).exists() {
        let _ = std::fs::remove_file(risk_pin_path);
    }
    host_risk_map.pin(risk_pin_path).context("Failed to pin HOST_RISK map")?;
    let mut host_risk_bpf: HashMap<_, u32, u32> = HashMap::try_from(host_risk_map)?;

    // Global Intelligence State
    let flow_table = Arc::new(RwLock::new(network_intelligence::flow_table::FlowTable::new(10_000, 30_000_000_000)));
    let security_graph = Arc::new(RwLock::new(network_intelligence::security_graph::SecurityGraph::new()));
    let event_counter = Arc::new(AtomicU64::new(0));

    // Event-driven telemetry path for TCP control events (SYN/FIN/RST)
    let mut perf_array = aya::maps::perf::PerfEventArray::try_from(ebpf.take_map("FLOW_EVENTS").ok_or_else(|| anyhow::anyhow!("FLOW_EVENTS map not found"))?)?;
    let cpus = aya::util::online_cpus().map_err(|e| anyhow::anyhow!("Failed to get online CPUs: {:?}", e))?;
    for cpu_id in cpus {
        let mut buf = perf_array.open(cpu_id, None)?;
        let ft = flow_table.clone();
        let sg = security_graph.clone();
        let ec = event_counter.clone();
        
        tokio::task::spawn_blocking(move || {
            loop {
                if buf.readable() {
                    buf.for_each(|event| match event {
                        aya::maps::perf::PerfEvent::Sample { head, tail: _ } => {
                            if head.len() < std::mem::size_of::<adg_xdp_common::FlowEvent>() {
                                return;
                            }
                            let event = unsafe { std::ptr::read_unaligned(head.as_ptr() as *const adg_xdp_common::FlowEvent) };
                            ec.fetch_add(1, Ordering::Relaxed);
                            
                            let mut ft_guard = ft.blocking_write();
                            let mut sg_guard = sg.blocking_write();
                            
                            let key = network_intelligence::flow_table::FlowKey {
                                src_ip: event.src_ip,
                                dst_ip: event.dst_ip,
                                src_port: event.src_port,
                                dst_port: event.dst_port,
                                protocol: event.protocol,
                            };
                            
                            let is_syn = (event.flags & 0x02) != 0;
                            let is_fin = (event.flags & 0x01) != 0;
                            let is_rst = (event.flags & 0x04) != 0;

                            ft_guard.insert_or_update(key, event.pkt_size as u64, event.timestamp_ns, is_syn, is_rst, is_fin);
                    
                            // Ensure nodes exist
                            sg_guard.add_node(network_intelligence::security_graph::GraphNode {
                                host_ip: event.src_ip, trust_score: 100, risk_level: 0
                            });
                            sg_guard.add_node(network_intelligence::security_graph::GraphNode {
                                host_ip: event.dst_ip, trust_score: 100, risk_level: 0
                            });
                            
                            // Build edge with live metadata from FlowTable
                            let mut flow_count = 0u32;
                            let mut unique_ports = std::collections::BTreeSet::new();
                            let mut total_pkts = 0u64;
                            let mut total_bytes = 0u64;
                            for (fk, fs) in ft_guard.iter() {
                                if fk.src_ip == event.src_ip && fk.dst_ip == event.dst_ip {
                                    flow_count += 1;
                                    unique_ports.insert(fk.dst_port);
                                    total_pkts += fs.packets;
                                    total_bytes += fs.bytes;
                                }
                            }
                            
                            let edge = network_intelligence::security_graph::GraphEdge {
                                src_ip: event.src_ip,
                                dst_ip: event.dst_ip,
                                packet_count: total_pkts,
                                byte_count: total_bytes,
                                flow_count,
                                unique_ports: unique_ports.len() as u32,
                                edge_risk: 0.0,
                                last_seen: event.timestamp_ns,
                            };
                            sg_guard.update_edge(edge);
                        }
                        _ => {}
                    });
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        });
    }

    // Track previous snapshots for windowed delta computation
    let mut prev_snapshots: collections::HashMap<Ipv4Addr, HostStats> = collections::HashMap::new();

    println!("Attached XDP program to {iface}. Monitoring HOST_STATS and populating HOST_TRUST map...");
    
    // Option C: Offline Intelligence Demo (satisfies compiler dead code checks by properly constructing and using all modules)
    println!("\nGenerating Network Intelligence Boot Report...");
    println!("{}", network_intelligence::demo::run_intelligence_demo());

    let ctrl_c = signal::ctrl_c();
    tokio::pin!(ctrl_c);

    loop {
        tokio::select! {
            _ = &mut ctrl_c => {
                println!("\nReceived Ctrl-C, exiting...");
                break;
            }
            _ = tokio::time::sleep(Duration::from_secs(2)) => {
                let mut entries = Vec::new();
                for item in host_stats.iter() {
                    if let Ok((ip, stats)) = item {
                        entries.push((Ipv4Addr::from(ip), stats));
                    }
                }
                if !entries.is_empty() {
                    entries.sort_by_key(|(_, stats)| std::cmp::Reverse(stats.packets));
                    println!("\n===== ADG TELEMETRY CYCLE =====");
                    println!("{:<16} | {:<12} | {:<12} | {:<12} | {:<10} | {:<12} | {:<8} | {:<10} | {:<10} | {:<12}", "Host", "Activity", "Protocol", "SYN", "Frag", "Recent", "Trust", "SYN Pen.", "Frag Pen.", "Level");
                    println!("---------------------------------------------------------------------------------------------------------------------------------------------------------------");
                    let current_time = get_ktime_ns();
                    
                    let ft_guard = flow_table.read().await;
                    let mut sg_guard = security_graph.write().await;
                    let expired_edges = sg_guard.remove_expired_edges(current_time, 30_000_000_000);

                    // Periodic graph analytics (once per poll cycle)
                    let components = network_intelligence::graph_algorithms::connected_components(&sg_guard);
                    let events_total = event_counter.load(Ordering::Relaxed);

                    for (ip, stats) in &entries {
                        // Compute windowed delta stats for behavioral classification.
                        // This ensures the profiler evaluates only recent activity,
                        // enabling natural trust recovery when malicious traffic stops.
                        let zero_stats = HostStats {
                            packets: 0, bytes: 0,
                            tcp_packets: 0, udp_packets: 0, icmp_packets: 0,
                            syn_packets: 0, frag_packets: 0, last_seen: 0,
                        };
                        let prev = prev_snapshots.get(ip).unwrap_or(&zero_stats);
                        let delta = compute_delta(stats, prev);

                        // Create HostProfile from windowed delta
                        let profile = HostProfiler::build((*ip).into(), &delta, current_time);
                        // Compute TrustScore
                        let trust = TrustEngine::compute(&profile);
                        
                        // Populate HOST_TRUST eBPF map
                        let trust_entry = TrustEntry {
                            score: trust.score,
                            level: trust.level() as u8,
                            version: 1,
                            flags: 0,
                        };
                        let ip_u32: u32 = (*ip).into();
                        if let Err(e) = host_trust.insert(ip_u32, trust_entry, 0) {
                            warn!("Failed to update HOST_TRUST for IP {}: {}", ip, e);
                        }

                        // Live Network Intelligence Integration
                        let ip_u32: u32 = (*ip).into();
                        
                        let mut context = network_intelligence::host_context::HostContextBuilder::build_for_host(
                            ip_u32,
                            &ft_guard,
                            (delta.packets as f64) / 2.0
                        );
                        
                        // Supplement context with live graph metrics
                        let neighbors = sg_guard.neighbors(ip_u32);
                        context.unique_dst_ips = std::cmp::max(context.unique_dst_ips, neighbors.len() as u32);
                        
                        // Compute weighted degree from live SecurityGraph
                        let (_in_deg, out_deg) = network_intelligence::graph_algorithms::weighted_degree(&sg_guard, ip_u32);
                        
                        let risk_score = network_intelligence::network_risk::NetworkRiskEngine::compute(trust.score, &context, out_deg);
                        let risk_score_val = (risk_score.total * 100.0) as u32;

                        // Run graph traversals for high-risk hosts
                        let mut blast_radius_len = 0usize;
                        let mut dfs_depth = 0usize;
                        if risk_score.total > 0.3 {
                            let bfs_result = network_intelligence::graph_algorithms::bfs(&sg_guard, ip_u32);
                            blast_radius_len = bfs_result.len();
                            let dfs_result = network_intelligence::graph_algorithms::dfs(&sg_guard, ip_u32);
                            dfs_depth = dfs_result.len();
                            debug!("Elevated risk host {}: BFS={}, DFS={}", ip, blast_radius_len, dfs_depth);
                        }

                        // Find which connected component this host belongs to
                        let component_size = components.iter()
                            .find(|c| c.contains(&ip_u32))
                            .map(|c| c.len())
                            .unwrap_or(0);

                        if let Err(e) = host_risk_bpf.insert(ip_u32, risk_score_val, 0) {
                            warn!("Failed to update HOST_RISK for IP {}: {}", ip, e);
                        }
                        
                        // Trust Engine output
                        println!("{:<16} | {:<12} | {:<12} | {:<12} | {:<10} | {:<12} | {:<8} | {:<10} | {:<10} | {:<12}",
                            std::net::Ipv4Addr::from(profile.ip).to_string(),
                            profile.activity.to_string(),
                            profile.protocol.to_string(),
                            profile.syn_behavior.to_string(),
                            profile.frag_behavior.to_string(),
                            profile.recent_activity.to_string(),
                            trust.score,
                            trust.syn_contribution,
                            trust.frag_contribution,
                            trust.level().to_string(),
                        );
                        
                        // Structured Network Intelligence report per host
                        println!("  [NI] Host: {}", ip);
                        println!("    Observed:  flows={}, unique_dst_ips={}, unique_dst_ports={}, rst_count={}",
                            context.flow_count, context.unique_dst_ips, context.unique_dst_ports, context.rst_count);
                        println!("    Rates:     {:.1} Bps, {:.1} Pps",
                            context.bytes_per_second, context.packets_per_second);
                        println!("    Graph:     weighted_out_degree={:.0}, neighbors={}, component_size={}, bfs_reach={}, dfs_depth={}",
                            out_deg, neighbors.len(), component_size, blast_radius_len, dfs_depth);
                        println!("    Risk:      total={:.4}, dest={:.3}, port_scan={:.3}, conn_fail={:.3}, centrality={:.3}",
                            risk_score.total, risk_score.destination_risk, risk_score.port_scan_risk,
                            risk_score.connection_failure_risk, risk_score.graph_centrality_risk);
                        println!("    Decision:  HOST_TRUST={}, HOST_RISK={}, policy=EXISTING",
                            trust.score, risk_score_val);
                    }

                    // Per-cycle graph summary
                    println!("--- Graph Summary: nodes={}, edges={}, components={}, expired_edges={}, flow_table_size={}, total_events={} ---",
                        sg_guard.node_count(), sg_guard.edge_count(), components.len(),
                        expired_edges, ft_guard.len(), events_total);
                    println!("===== END CYCLE =====\n");

                    // Update previous snapshots for next window
                    for (ip, stats) in entries {
                        prev_snapshots.insert(ip, stats);
                    }
                } else {
                    debug!("HOST_STATS map currently empty.");
                }
            }
        }
    }

    Ok(())
}
