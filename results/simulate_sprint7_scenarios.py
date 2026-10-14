import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
import os

def generate_port_scan_with_rst():
    # Case E: High RST ratio + Port scan (Sprint 7 feature)
    times = list(range(61))
    trusts = []
    actions = []
    rst_ratios = []
    unique_ports = []
    
    trust = 100
    for t in times:
        if 10 < t <= 20:
            # Active port scan phase
            rst_ratio = min(0.9, (t - 10) * 0.09)
            ports = (t - 10) * 15
            trust = max(10, 100 - int(rst_ratio * 50 + (ports / 150) * 40))
        elif 20 < t <= 35:
            # Sustained scan
            rst_ratio = 0.85
            ports = 150
            trust = 10
        elif t > 35:
            # Recovery
            rst_ratio = max(0.0, 0.85 - (t - 35) * 0.06)
            ports = max(1, 150 - (t - 35) * 10)
            trust = min(100, 10 + int((t - 35) * 4.5))
        else:
            rst_ratio = 0.02
            ports = 2
            trust = 100
            
        trusts.append(trust)
        actions.append(get_action(trust))
        rst_ratios.append(round(rst_ratio, 2))
        unique_ports.append(ports)
        
    return pd.DataFrame({
        'Time_Seconds': times,
        'Trust_Score': trusts,
        'Policy_Action': actions,
        'RST_Ratio': rst_ratios,
        'Unique_Ports': unique_ports
    })

def generate_lateral_movement_case():
    # Case F: Rapid contact with multiple internal IP destinations (Sprint 7 feature)
    times = list(range(61))
    trusts = []
    actions = []
    unique_dst_ips = []
    
    trust = 100
    for t in times:
        if 12 < t <= 25:
            # Spreading laterally across internal hosts
            dst_ips = (t - 12) * 2
            # Penalty for high destination diversity
            trust = max(15, 100 - dst_ips * 3.5)
        elif 25 < t <= 40:
            dst_ips = 26
            trust = 15
        elif t > 40:
            dst_ips = max(1, 26 - (t - 40) * 1.5)
            trust = min(100, 15 + int((t - 40) * 4.25))
        else:
            dst_ips = 1
            trust = 100
            
        trusts.append(trust)
        actions.append(get_action(trust))
        unique_dst_ips.append(int(dst_ips))
        
    return pd.DataFrame({
        'Time_Seconds': times,
        'Trust_Score': trusts,
        'Policy_Action': actions,
        'Unique_Dst_IPs': unique_dst_ips
    })

def get_action(trust):
    if trust >= 90: return "ALLOW"
    elif trust >= 70: return "ALLOW"
    elif trust >= 40: return "MIRROR"
    elif trust >= 20: return "REDIRECT"
    else: return "DROP"

def plot_sprint7_scenarios(df_rst, df_lateral):
    fig, axes = plt.subplots(2, 1, figsize=(10, 8), sharex=True)
    
    # Plot 1: Port Scan with RST
    ax1 = axes[0]
    ax1.plot(df_rst['Time_Seconds'], df_rst['Trust_Score'], color='#2c3e50', linewidth=3, label='Trust Score')
    ax1_twin = ax1.twinx()
    ax1_twin.plot(df_rst['Time_Seconds'], df_rst['RST_Ratio'] * 100, color='#e74c3c', linestyle='--', linewidth=2, label='RST Ratio (%)')
    
    ax1.axhspan(90, 100, color='#2ecc71', alpha=0.15)
    ax1.axhspan(40, 89, color='#f39c12', alpha=0.15)
    ax1.axhspan(20, 39, color='#e67e22', alpha=0.15)
    ax1.axhspan(0, 19, color='#e74c3c', alpha=0.15)
    
    ax1.set_title('Sprint 7 Telemetry: High TCP RST Ratio + Port Scan Detection', fontsize=13, fontweight='bold')
    ax1.set_ylabel('Trust Score', fontsize=11)
    ax1_twin.set_ylabel('RST Ratio (%)', fontsize=11, color='#e74c3c')
    ax1.set_ylim(0, 105)
    ax1.grid(True, linestyle='--', alpha=0.6)
    
    # Combine legends for ax1
    lines1, labels1 = ax1.get_legend_handles_labels()
    lines2, labels2 = ax1_twin.get_legend_handles_labels()
    ax1.legend(lines1 + lines2, labels1 + labels2, loc='center right')

    # Plot 2: Lateral Movement
    ax2 = axes[1]
    ax2.plot(df_lateral['Time_Seconds'], df_lateral['Trust_Score'], color='#2c3e50', linewidth=3, label='Trust Score')
    ax2_twin = ax2.twinx()
    ax2_twin.plot(df_lateral['Time_Seconds'], df_lateral['Unique_Dst_IPs'], color='#8e44ad', linestyle='-.', linewidth=2, label='Unique Dst IPs')
    
    ax2.axhspan(90, 100, color='#2ecc71', alpha=0.15)
    ax2.axhspan(40, 89, color='#f39c12', alpha=0.15)
    ax2.axhspan(20, 39, color='#e67e22', alpha=0.15)
    ax2.axhspan(0, 19, color='#e74c3c', alpha=0.15)
    
    ax2.set_title('Sprint 7 Telemetry: Lateral Movement & Internal Subnet Scanning', fontsize=13, fontweight='bold')
    ax2.set_xlabel('Time (seconds)', fontsize=12)
    ax2.set_ylabel('Trust Score', fontsize=11)
    ax2_twin.set_ylabel('Unique Dst IPs', fontsize=11, color='#8e44ad')
    ax2.set_ylim(0, 105)
    ax2.set_xlim(0, 60)
    ax2.grid(True, linestyle='--', alpha=0.6)
    
    lines3, labels3 = ax2.get_legend_handles_labels()
    lines4, labels4 = ax2_twin.get_legend_handles_labels()
    ax2.legend(lines3 + lines4, labels3 + labels4, loc='center right')

    plt.tight_layout()
    plt.savefig('results/figure_sprint7_scenarios.png', dpi=300)
    print("Saved results/figure_sprint7_scenarios.png")

def main():
    df_rst = generate_port_scan_with_rst()
    df_lateral = generate_lateral_movement_case()
    
    df_rst.to_csv('results/case_e_portscan_rst.csv', index=False)
    df_lateral.to_csv('results/case_f_lateral.csv', index=False)
    
    plot_sprint7_scenarios(df_rst, df_lateral)
    print("Sprint 7 telemetry scenarios generated and plotted successfully!")

if __name__ == "__main__":
    main()
