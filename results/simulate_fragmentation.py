import pandas as pd
import matplotlib.pyplot as plt
import os

def generate_fragmentation_attack():
    # Rapid fragmentation attack (e.g. hping3 -f)
    # Trust plummets heavily due to fragmentation penalty
    times = list(range(61))
    trusts = []
    actions = []
    trust = 100
    for t in times:
        if 15 < t <= 20:
            trust -= 20 # Attack begins, drops rapidly to 15 (85 penalty)
        elif 20 < t <= 35:
            trust = 15
        elif t > 35:
            trust += 5 # Attack stops, recovery begins
            
        trust = max(0, min(100, trust))
        trusts.append(trust)
        
        if trust >= 90: action = "ALLOW"
        elif trust >= 70: action = "ALLOW"
        elif trust >= 40: action = "MIRROR"
        elif trust >= 20: action = "REDIRECT"
        else: action = "DROP"
        
        actions.append(action)
        
    return pd.DataFrame({'Time_Seconds': times, 'Trust_Score': trusts, 'Policy_Action': actions})

def plot_fragmentation(df):
    plt.figure(figsize=(10, 6))
    
    plt.plot(df['Time_Seconds'], df['Trust_Score'], label='Host Trust Score (Fragment Attack)', color='#8e44ad', linewidth=3)
    
    plt.axhspan(90, 100, color='#2ecc71', alpha=0.2, label='ALLOW Zone')
    plt.axhspan(40, 89, color='#f39c12', alpha=0.2, label='MIRROR Zone')
    plt.axhspan(20, 39, color='#e67e22', alpha=0.2, label='REDIRECT Zone')
    plt.axhspan(0, 19, color='#e74c3c', alpha=0.2, label='DROP Zone')
    
    # Annotations
    plt.annotate('hping3 -f starts', xy=(15, 100), xytext=(20, 105),
                 arrowprops=dict(facecolor='black', shrink=0.05), fontsize=12)
    plt.annotate('Trust plunges to 15\n(Fragmentation Penalty)', xy=(20, 15), xytext=(25, 40),
                 arrowprops=dict(facecolor='black', shrink=0.05), fontsize=12)
                 
    plt.title('Dynamic Trust Response: Fragmented Packet Attack (Teardrop / Evasion)', fontsize=16, fontweight='bold')
    plt.xlabel('Time (seconds)', fontsize=14)
    plt.ylabel('Trust Score', fontsize=14)
    plt.ylim(0, 110)
    plt.xlim(0, 60)
    plt.grid(True, linestyle='--', alpha=0.7)
    plt.legend(loc='lower left')
    
    plt.tight_layout()
    plt.savefig('results/figure_fragmentation_attack.png', dpi=300)
    print("Saved results/figure_fragmentation_attack.png")

def main():
    df = generate_fragmentation_attack()
    df.to_csv('results/case_d_fragmentation.csv', index=False)
    plot_fragmentation(df)
    print("Generated fragmentation attack simulation!")

if __name__ == "__main__":
    main()
