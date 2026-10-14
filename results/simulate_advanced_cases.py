import pandas as pd
import matplotlib.pyplot as plt
import os

def generate_stealth_attack():
    # Gradual decline, never hitting DROP, isolating in MIRROR
    times = list(range(61))
    trusts = []
    actions = []
    trust = 100
    for t in times:
        if 10 < t <= 40:
            trust -= 2  # Slow decline
        elif t > 40:
            trust = max(45, trust) # Hovers at MIRROR
            
        trust = max(0, min(100, trust))
        trusts.append(trust)
        actions.append(get_action(trust))
        
    return pd.DataFrame({'Time_Seconds': times, 'Trust_Score': trusts, 'Policy_Action': actions})

def generate_port_scan():
    # Sudden drop to 0, stays for a bit, slow recovery
    times = list(range(61))
    trusts = []
    actions = []
    trust = 100
    for t in times:
        if t == 15:
            trust = 10
        elif 15 < t <= 25:
            trust = 10
        elif t > 25:
            trust += 2.5 # Slow recovery
            
        trust = max(0, min(100, trust))
        trusts.append(trust)
        actions.append(get_action(trust))
        
    return pd.DataFrame({'Time_Seconds': times, 'Trust_Score': trusts, 'Policy_Action': actions})

def generate_oscillating_attack():
    # Attacker games the system: Attack -> Wait -> Attack
    times = list(range(61))
    trusts = []
    actions = []
    trust = 100
    for t in times:
        if 10 < t <= 15: trust -= 20 # Attack 1
        elif 15 < t <= 35: trust += 5 # Recovery
        elif 35 < t <= 40: trust -= 20 # Attack 2
        elif t > 40: trust += 5 # Recovery
            
        trust = max(0, min(100, trust))
        trusts.append(trust)
        actions.append(get_action(trust))
        
    return pd.DataFrame({'Time_Seconds': times, 'Trust_Score': trusts, 'Policy_Action': actions})

def get_action(trust):
    if trust >= 90: return "ALLOW"
    elif trust >= 70: return "ALLOW"
    elif trust >= 40: return "MIRROR"
    elif trust >= 20: return "REDIRECT"
    else: return "DROP"

def plot_combined_cases(df1, df2, df3):
    fig, axes = plt.subplots(3, 1, figsize=(10, 12), sharex=True)
    
    cases = [
        (df1, 'Case A: Stealth Slow-Rate Attack (Isolates to MIRROR)', axes[0]),
        (df2, 'Case B: Sudden Port Scan (Immediate DROP & Slow Recovery)', axes[1]),
        (df3, 'Case C: Oscillating Attacker (Gaming the Trust System)', axes[2])
    ]
    
    for df, title, ax in cases:
        ax.plot(df['Time_Seconds'], df['Trust_Score'], color='#2c3e50', linewidth=3)
        
        ax.axhspan(90, 100, color='#2ecc71', alpha=0.2)
        ax.axhspan(40, 89, color='#f39c12', alpha=0.2)
        ax.axhspan(20, 39, color='#e67e22', alpha=0.2)
        ax.axhspan(0, 19, color='#e74c3c', alpha=0.2)
        
        ax.set_title(title, fontsize=14, fontweight='bold')
        ax.set_ylabel('Trust Score', fontsize=12)
        ax.set_ylim(0, 105)
        ax.set_xlim(0, 60)
        ax.grid(True, linestyle='--', alpha=0.7)
        
    axes[2].set_xlabel('Time (seconds)', fontsize=14)
    
    plt.tight_layout()
    plt.savefig('results/figure_advanced_cases.png', dpi=300)
    print("Saved results/figure_advanced_cases.png")

def main():
    df1 = generate_stealth_attack()
    df2 = generate_port_scan()
    df3 = generate_oscillating_attack()
    
    # Save CSVs
    df1.to_csv('results/case_a_stealth.csv', index=False)
    df2.to_csv('results/case_b_portscan.csv', index=False)
    df3.to_csv('results/case_c_oscillating.csv', index=False)
    
    plot_combined_cases(df1, df2, df3)
    print("Generated 3 new scenarios!")

if __name__ == "__main__":
    main()
