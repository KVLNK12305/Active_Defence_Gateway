import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import numpy as np
import os

def create_synthetic_data(csv_file):
    print(f"Creating synthetic dataset at {csv_file} for demonstration...")
    # Generate 60 seconds of data: 0-15 (Normal), 16-30 (Attack), 31-45 (Attack Continues), 46-60 (Recovery)
    times = list(range(61))
    trusts = []
    actions = []
    
    for t in times:
        if t <= 15:
            trust = 100
        elif t <= 20:
            trust = 100 - (t - 15) * 10 # Plunges to 50
        elif t <= 30:
            trust = 50
        elif t <= 35:
            trust = 50 - (t - 30) * 7 # Plunges to 15
        elif t <= 45:
            trust = 15
        elif t <= 55:
            trust = 15 + (t - 45) * 8.5 # Recovers
        else:
            trust = 100
            
        trust = max(0, min(100, trust))
        trusts.append(trust)
        
        if trust >= 90: action = "ALLOW"
        elif trust >= 70: action = "ALLOW" # LOG mapped to ALLOW functionally
        elif trust >= 40: action = "MIRROR"
        elif trust >= 20: action = "REDIRECT"
        else: action = "DROP"
        
        actions.append(action)
        
    df = pd.DataFrame({
        'Time_Seconds': times,
        'Trust_Score': trusts,
        'Policy_Action': actions
    })
    df.to_csv(csv_file, index=False)
    return df

def plot_trust_vs_time(df):
    plt.figure(figsize=(10, 6))
    
    # Plot Trust Score
    plt.plot(df['Time_Seconds'], df['Trust_Score'], label='Host Trust Score', color='#2c3e50', linewidth=3)
    
    # Background colors for policy zones
    plt.axhspan(90, 100, color='#2ecc71', alpha=0.2, label='ALLOW Zone')
    plt.axhspan(40, 89, color='#f39c12', alpha=0.2, label='MIRROR Zone')
    plt.axhspan(20, 39, color='#e67e22', alpha=0.2, label='REDIRECT Zone')
    plt.axhspan(0, 19, color='#e74c3c', alpha=0.2, label='DROP Zone')
    
    plt.title('Dynamic Trust Enforcement over Time', fontsize=16, fontweight='bold')
    plt.xlabel('Time (seconds)', fontsize=14)
    plt.ylabel('Trust Score', fontsize=14)
    plt.ylim(0, 105)
    plt.xlim(0, max(df['Time_Seconds']))
    plt.grid(True, linestyle='--', alpha=0.7)
    plt.legend(loc='lower left')
    
    plt.tight_layout()
    plt.savefig('figure_4_trust_vs_time.png', dpi=300)
    print("Saved figure_4_trust_vs_time.png")

def plot_telemetry_dashboard():
    # Synthetic bar chart for Host Telemetry
    labels = ['Normal Traffic', 'Moderate SYN', 'Aggressive SYN']
    syn_ratios = [0.05, 0.45, 0.95]
    trust_scores = [100, 80, 15]
    
    x = np.arange(len(labels))
    width = 0.35
    
    fig, ax1 = plt.subplots(figsize=(10, 6))
    
    rects1 = ax1.bar(x - width/2, [r*100 for r in syn_ratios], width, label='SYN Ratio (%)', color='#e74c3c')
    ax2 = ax1.twinx()
    rects2 = ax2.bar(x + width/2, trust_scores, width, label='Trust Score', color='#3498db')
    
    ax1.set_ylabel('SYN Ratio (%)', fontsize=14, color='#e74c3c')
    ax2.set_ylabel('Calculated Trust Score', fontsize=14, color='#3498db')
    ax1.set_xticks(x)
    ax1.set_xticklabels(labels, fontsize=12)
    
    plt.title('Host Profiling & Trust Score Correlation', fontsize=16, fontweight='bold')
    
    # Add a unified legend
    lines1, labels1 = ax1.get_legend_handles_labels()
    lines2, labels2 = ax2.get_legend_handles_labels()
    ax1.legend(lines1 + lines2, labels1 + labels2, loc='upper center')
    
    plt.tight_layout()
    plt.savefig('figure_7_telemetry_dashboard.png', dpi=300)
    print("Saved figure_7_telemetry_dashboard.png")

def main():
    csv_file = "experiment_data.csv"
    if not os.path.exists(csv_file):
        df = create_synthetic_data(csv_file)
    else:
        df = pd.read_csv(csv_file)
        
    plot_trust_vs_time(df)
    plot_telemetry_dashboard()
    print("All figures generated successfully! Check the current directory.")

if __name__ == "__main__":
    main()
