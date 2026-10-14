# ADG Experimental Evaluation Results

This document contains the formatted tables and placeholders for the figures generated during the Sprint 6.5 validation phase.

## Experiment 7: Trust Engine Validation

| Scenario   | SYN Behaviour | Expected Trust |
| ---------- | ------------- | -------------: |
| Normal     | Normal        |            100 |
| Moderate   | Moderate      |             80 |
| Aggressive | Aggressive    |             15 |

## Experiment 8: Controller Decision Validation

| Trust Score | Derived Action |
| ----------- | -------------- |
| 100         | ALLOW          |
| 80          | ALLOW (LOG)    |
| 50          | MIRROR         |
| 15          | DROP           |

## Experiment 9: End-to-End Pipeline Demonstration

### Figure 4: Dynamic Trust Enforcement over Time
*(Embed `results/figure_4_trust_vs_time.png` here after running `plot_thesis_figures.py`)*

### Figure 7: Host Profiling & Trust Score Correlation
*(Embed `results/figure_7_telemetry_dashboard.png` here after running `plot_thesis_figures.py`)*

### Audit Logs (Escalation & Recovery)
```text
[TRUST UPDATE]
Host        : 10.0.0.1
Trust       : 15
Policy      : MIRROR -> DROP
Time        : 14:52:31
```
