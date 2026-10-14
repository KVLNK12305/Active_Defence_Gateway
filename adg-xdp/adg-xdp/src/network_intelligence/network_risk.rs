use super::host_context::HostNetworkContext;
use crate::telemetry_extensions::{destination_diversity, port_scan_score, rst_ratio};

// Named weight constants for network risk components
pub const W_DESTINATION_RISK: f64 = 0.25;
pub const W_PORT_SCAN_RISK: f64 = 0.25;
pub const W_CONNECTION_FAILURE_RISK: f64 = 0.25;
pub const W_GRAPH_CENTRALITY_RISK: f64 = 0.25;

/// Length (seconds) of the FlowTable window over which `HostNetworkContext` rates are expressed.
/// Must equal the FlowTable timeout used by the daemon (30 s).
pub const FLOW_WINDOW_SECS: f64 = 30.0;

#[derive(Debug, Clone, PartialEq)]
pub struct NetworkRiskScore {
    pub total: f64,
    pub destination_risk: f64,
    pub port_scan_risk: f64,
    pub connection_failure_risk: f64,
    pub graph_centrality_risk: f64,
}

pub struct NetworkRiskEngine;

impl NetworkRiskEngine {
    /// Computes the Network Risk Score (0.0 to 1.0) based on network context and graph centrality.
    ///
    /// Formula:
    /// network_risk = w1 * destination_risk +
    ///                w2 * port_scan_risk +
    ///                w3 * connection_failure_risk +
    ///                w4 * graph_centrality_risk
    ///
    /// Note: This is an independent research metric and does NOT modify TrustEngine scores.
    pub fn compute(
        _host_trust_score: u8,
        context: &HostNetworkContext,
        weighted_out_degree: f64,
    ) -> NetworkRiskScore {
        // Every component is a ratio clamped to [0,1] so no single signal can dominate the total.
        let dest_risk = destination_diversity(context.unique_dst_ips, context.flow_count).clamp(0.0, 1.0);

        // Flow events observed in the window (rate * window). Zero events => zero score
        // (port_scan_score returns 0.0 for a zero denominator).
        let total_packets = (context.packets_per_second * FLOW_WINDOW_SECS).round() as u64;
        let port_risk = port_scan_score(context.unique_dst_ports, total_packets).clamp(0.0, 1.0);

        let conn_fail_risk = rst_ratio(context.rst_count, context.flow_count as u64).clamp(0.0, 1.0);

        // Normalize graph centrality risk based on weighted out-degree
        let centrality_risk = (weighted_out_degree / 50_000.0).clamp(0.0, 1.0);

        let total = (W_DESTINATION_RISK * dest_risk)
            + (W_PORT_SCAN_RISK * port_risk)
            + (W_CONNECTION_FAILURE_RISK * conn_fail_risk)
            + (W_GRAPH_CENTRALITY_RISK * centrality_risk);

        NetworkRiskScore {
            total: total.clamp(0.0, 1.0),
            destination_risk: dest_risk,
            port_scan_risk: port_risk,
            connection_failure_risk: conn_fail_risk,
            graph_centrality_risk: centrality_risk,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_risk_calculation_low_risk() {
        let ctx = HostNetworkContext {
            host_ip: 1,
            unique_dst_ips: 1,
            unique_dst_ports: 1,
            flow_count: 50,
            rst_count: 0,
            bytes_per_second: 1000.0,
            packets_per_second: 10.0,
            min_packet_size: 64,
            max_packet_size: 1500,
        };

        let score = NetworkRiskEngine::compute(100, &ctx, 2000.0);
        assert!(score.total < 0.2, "Normal traffic should produce low network risk");
    }

    #[test]
    fn test_network_risk_calculation_reconnaissance() {
        let ctx = HostNetworkContext {
            host_ip: 1,
            unique_dst_ips: 40,
            unique_dst_ports: 40,
            flow_count: 45,
            rst_count: 35,
            bytes_per_second: 50000.0,
            packets_per_second: 50.0,
            min_packet_size: 40,
            max_packet_size: 60,
        };

        let score = NetworkRiskEngine::compute(50, &ctx, 60000.0);
        assert!(score.destination_risk > 0.8);
        assert!(score.connection_failure_risk > 0.7);
        assert!(score.graph_centrality_risk == 1.0);
        assert!(score.total > 0.6, "Reconnaissance behavior should yield high network risk");
    }

    // ===== BRUTAL EDGE CASES =====

    #[test]
    fn test_zero_everything_produces_zero_risk() {
        let ctx = HostNetworkContext {
            host_ip: 0x0A000001,
            unique_dst_ips: 0,
            unique_dst_ports: 0,
            flow_count: 0,
            rst_count: 0,
            bytes_per_second: 0.0,
            packets_per_second: 0.0,
            min_packet_size: 0,
            max_packet_size: 0,
        };
        let score = NetworkRiskEngine::compute(100, &ctx, 0.0);
        assert_eq!(score.total, 0.0);
        assert_eq!(score.destination_risk, 0.0);
        assert_eq!(score.port_scan_risk, 0.0);
        assert_eq!(score.connection_failure_risk, 0.0);
        assert_eq!(score.graph_centrality_risk, 0.0);
    }

    #[test]
    fn test_maximum_all_signals() {
        let ctx = HostNetworkContext {
            host_ip: 0x0A000001,
            unique_dst_ips: 100,
            unique_dst_ports: 100,
            flow_count: 100,
            rst_count: 100,
            bytes_per_second: 100000.0,
            packets_per_second: 100.0,
            min_packet_size: 40,
            max_packet_size: 40,
        };
        let score = NetworkRiskEngine::compute(0, &ctx, 100_000.0);
        assert!(score.total <= 1.0, "Risk score must be clamped to 1.0");
        assert_eq!(score.graph_centrality_risk, 1.0);
        assert_eq!(score.destination_risk, 1.0);
        assert_eq!(score.connection_failure_risk, 1.0);
    }

    #[test]
    fn test_only_destination_diversity_signal() {
        let ctx = HostNetworkContext {
            host_ip: 0x0A000001,
            unique_dst_ips: 50,
            unique_dst_ports: 1,
            flow_count: 50,
            rst_count: 0,
            bytes_per_second: 100.0,
            packets_per_second: 1.0,
            min_packet_size: 64,
            max_packet_size: 1500,
        };
        let score = NetworkRiskEngine::compute(100, &ctx, 0.0);
        assert!(score.destination_risk > 0.9, "High destination diversity");
        assert_eq!(score.connection_failure_risk, 0.0, "No RST");
        assert_eq!(score.graph_centrality_risk, 0.0, "Zero out-degree");
    }

    #[test]
    fn test_only_rst_signal() {
        let ctx = HostNetworkContext {
            host_ip: 0x0A000001,
            unique_dst_ips: 1,
            unique_dst_ports: 1,
            flow_count: 10,
            rst_count: 10,
            bytes_per_second: 100.0,
            packets_per_second: 1.0,
            min_packet_size: 64,
            max_packet_size: 64,
        };
        let score = NetworkRiskEngine::compute(80, &ctx, 0.0);
        assert_eq!(score.connection_failure_risk, 1.0, "All flows RST");
        assert!(score.destination_risk < 0.15, "Low diversity");
    }

    #[test]
    fn test_weights_sum_to_one() {
        let sum = W_DESTINATION_RISK + W_PORT_SCAN_RISK + W_CONNECTION_FAILURE_RISK + W_GRAPH_CENTRALITY_RISK;
        assert!((sum - 1.0).abs() < 1e-9, "Risk weights must sum to 1.0");
    }

    #[test]
    fn test_trust_score_not_used_in_computation() {
        // NetworkRiskEngine takes trust_score but currently ignores it (_host_trust_score)
        // Verify same context with different trust produces same risk
        let ctx = HostNetworkContext {
            host_ip: 0x0A000001,
            unique_dst_ips: 10,
            unique_dst_ports: 5,
            flow_count: 20,
            rst_count: 3,
            bytes_per_second: 5000.0,
            packets_per_second: 50.0,
            min_packet_size: 64,
            max_packet_size: 1500,
        };
        let score_trusted = NetworkRiskEngine::compute(100, &ctx, 10000.0);
        let score_untrusted = NetworkRiskEngine::compute(0, &ctx, 10000.0);
        assert_eq!(score_trusted.total, score_untrusted.total);
    }

    #[test]
    fn test_idle_host_with_many_ports_has_bounded_port_risk() {
        // Regression: zero packet rate used to make port score = unique_ports / 1 (unbounded).
        let ctx = HostNetworkContext {
            host_ip: 1, unique_dst_ips: 1, unique_dst_ports: 100, flow_count: 100, rst_count: 0,
            bytes_per_second: 0.0, packets_per_second: 0.0, min_packet_size: 0, max_packet_size: 0,
        };
        let score = NetworkRiskEngine::compute(100, &ctx, 0.0);
        assert_eq!(score.port_scan_risk, 0.0, "no events in window => no port-scan evidence");
        assert!(score.total < 0.1);
    }

    #[test]
    fn test_all_components_individually_clamped() {
        let ctx = HostNetworkContext {
            host_ip: 1, unique_dst_ips: 100, unique_dst_ports: 500, flow_count: 10, rst_count: 50,
            bytes_per_second: 1.0, packets_per_second: 0.1, min_packet_size: 40, max_packet_size: 40,
        };
        let s = NetworkRiskEngine::compute(100, &ctx, 0.0);
        assert!(s.destination_risk <= 1.0 && s.port_scan_risk <= 1.0 && s.connection_failure_risk <= 1.0);
    }
}
