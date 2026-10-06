use crate::profiler::{FragBehavior, HostProfile, SynBehavior};

// ===== Penalty Constants =====
const MODERATE_SYN_PENALTY: i32 = 20;
const AGGRESSIVE_SYN_PENALTY: i32 = 50;
const FRAGMENTATION_PENALTY: i32 = 85;

// ===== TrustScore =====
pub struct TrustScore {
    pub score: u8,
    pub syn_contribution: i32,
    pub frag_contribution: i32,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TrustLevel {
    Trusted,    // 90..=100 -> ALLOW (Priority 1)
    Normal,     // 70..=89  -> ALLOW (LOG) (Priority 1)
    Suspicious, // 40..=69  -> MIRROR (Priority 120)
    Untrusted,  // 0..=39   -> DROP (Priority 200)
}

impl std::fmt::Display for TrustLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TrustLevel::Trusted => write!(f, "TRUSTED"),
            TrustLevel::Normal => write!(f, "NORMAL"),
            TrustLevel::Suspicious => write!(f, "SUSPICIOUS"),
            TrustLevel::Untrusted => write!(f, "UNTRUSTED"),
        }
    }
}

impl TrustScore {
    pub fn level(&self) -> TrustLevel {
        match self.score {
            90..=100 => TrustLevel::Trusted,
            70..=89 => TrustLevel::Normal,
            40..=69 => TrustLevel::Suspicious,
            _ => TrustLevel::Untrusted,
        }
    }
}

// ===== TrustEngine =====
pub struct TrustEngine;

impl TrustEngine {
    /// Computes trust score using SYN behavior and fragmentation analysis.
    pub fn compute(profile: &HostProfile) -> TrustScore {
        let mut trust: i32 = 100;
        let mut syn_contribution: i32 = 0;
        let mut frag_contribution: i32 = 0;

        // Security Signals - SYN Behavior
        match profile.syn_behavior {
            SynBehavior::Normal => {}
            SynBehavior::Moderate => {
                syn_contribution = -MODERATE_SYN_PENALTY;
                trust += syn_contribution;
            }
            SynBehavior::Aggressive => {
                syn_contribution = -AGGRESSIVE_SYN_PENALTY;
                trust += syn_contribution;
            }
            SynBehavior::Unknown => {}
        }

        // Security Signals - Fragmentation
        match profile.frag_behavior {
            FragBehavior::Normal => {}
            FragBehavior::Anomalous => {
                frag_contribution = -FRAGMENTATION_PENALTY;
                trust += frag_contribution;
            }
        }

        trust = trust.clamp(0, 100);

        TrustScore {
            score: trust as u8,
            syn_contribution,
            frag_contribution,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profiler::{ActivityLevel, HostProfile, ProtocolProfile, RecentActivity};

    fn create_profile(syn: SynBehavior) -> HostProfile {
        HostProfile {
            ip: 0x0A000001,
            packets: 1000,
            bytes: 100000,
            tcp: 100,
            frag: 0,
            udp: 0,
            icmp: 0,
            syn: 5,
            last_seen: 1,
            activity: ActivityLevel::High,
            protocol: ProtocolProfile::TcpDominant,
            syn_behavior: syn,
            frag_behavior: FragBehavior::Normal,
            recent_activity: RecentActivity::Active,
        }
    }

    #[test]
    fn test_normal_syn_full_trust() {
        let profile = create_profile(SynBehavior::Normal);
        let score = TrustEngine::compute(&profile);
        assert_eq!(score.score, 100);
        assert_eq!(score.syn_contribution, 0);
        assert_eq!(score.level(), TrustLevel::Trusted);
    }

    #[test]
    fn test_moderate_syn_deduction() {
        let profile = create_profile(SynBehavior::Moderate);
        let score = TrustEngine::compute(&profile);
        assert_eq!(score.score, 80);
        assert_eq!(score.syn_contribution, -20);
        assert_eq!(score.level(), TrustLevel::Normal);
    }

    #[test]
    fn test_aggressive_syn_deduction() {
        let profile = create_profile(SynBehavior::Aggressive);
        let score = TrustEngine::compute(&profile);
        assert_eq!(score.score, 50);
        assert_eq!(score.syn_contribution, -50);
        assert_eq!(score.level(), TrustLevel::Suspicious);
    }

    #[test]
    fn test_anomalous_fragmentation_deduction() {
        let mut profile = create_profile(SynBehavior::Normal);
        profile.frag_behavior = FragBehavior::Anomalous;
        let score = TrustEngine::compute(&profile);
        assert_eq!(score.score, 15);
        assert_eq!(score.frag_contribution, -85);
        assert_eq!(score.level(), TrustLevel::Untrusted);
    }

    #[test]
    fn test_combined_aggressive_syn_and_frag_clamped_to_zero() {
        let mut profile = create_profile(SynBehavior::Aggressive);
        profile.frag_behavior = FragBehavior::Anomalous;
        let score = TrustEngine::compute(&profile);
        assert_eq!(score.score, 0);
        assert_eq!(score.syn_contribution, -50);
        assert_eq!(score.frag_contribution, -85);
        assert_eq!(score.level(), TrustLevel::Untrusted);
    }

    #[test]
    fn test_unknown_syn_no_penalty() {
        let profile = create_profile(SynBehavior::Unknown);
        let score = TrustEngine::compute(&profile);
        assert_eq!(score.score, 100);
        assert_eq!(score.syn_contribution, 0);
        assert_eq!(score.level(), TrustLevel::Trusted);
    }

    #[test]
    fn test_high_activity_no_penalty() {
        let mut profile = create_profile(SynBehavior::Normal);
        profile.activity = ActivityLevel::High;
        profile.packets = 1_000_000;
        let score = TrustEngine::compute(&profile);
        assert_eq!(score.score, 100, "High activity should not reduce trust");
    }

    #[test]
    fn test_idle_no_penalty() {
        let mut profile = create_profile(SynBehavior::Normal);
        profile.activity = ActivityLevel::Idle;
        profile.packets = 5;
        let score = TrustEngine::compute(&profile);
        assert_eq!(score.score, 100, "Idle hosts should not be penalized");
    }

    #[test]
    fn test_udp_dominant_no_penalty() {
        let mut profile = create_profile(SynBehavior::Normal);
        profile.protocol = ProtocolProfile::UdpDominant;
        profile.udp = 1000;
        let score = TrustEngine::compute(&profile);
        assert_eq!(score.score, 100, "UDP is legitimate (DNS, QUIC, VoIP)");
    }

    #[test]
    fn test_icmp_dominant_no_penalty() {
        let mut profile = create_profile(SynBehavior::Normal);
        profile.protocol = ProtocolProfile::IcmpDominant;
        profile.icmp = 500;
        let score = TrustEngine::compute(&profile);
        assert_eq!(score.score, 100, "ICMP is diagnostic, not malicious");
    }
}