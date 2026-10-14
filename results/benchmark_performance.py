import time
import os
import sys
import numpy as np
import pandas as pd

# Add controller path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../controller')))
from policy import PolicyEngine, PolicyAction  # type: ignore[import-not-found]
from trust import TrustStore  # type: ignore[import-not-found]

def benchmark_policy_engine_throughput(iterations=100000):
    engine = PolicyEngine()
    test_scores = [100, 95, 80, 50, 25, 10, 0]
    
    start_time = time.perf_counter()
    for i in range(iterations):
        score = test_scores[i % len(test_scores)]
        action = engine.evaluate(score)
    end_time = time.perf_counter()
    
    total_time_ms = (end_time - start_time) * 1000
    avg_latency_us = (total_time_ms * 1000) / iterations
    throughput_ops_sec = iterations / (end_time - start_time)
    
    return {
        'iterations': iterations,
        'total_time_ms': round(total_time_ms, 2),
        'avg_latency_us': round(avg_latency_us, 4),
        'throughput_ops_sec': int(throughput_ops_sec)
    }

def benchmark_trust_lookup_scaling(num_hosts=10000):
    store = TrustStore()
    ips = [f"10.{i // 65536}.{(i // 256) % 256}.{i % 256}" for i in range(min(num_hosts, 5000))]
    
    start_time = time.perf_counter()
    for ip in ips:
        score = store.get(ip)
    end_time = time.perf_counter()
    
    total_time_ms = (end_time - start_time) * 1000
    avg_lookup_us = (total_time_ms * 1000) / len(ips)
    
    return {
        'num_hosts': len(ips),
        'total_time_ms': round(total_time_ms, 2),
        'avg_lookup_us': round(avg_lookup_us, 4)
    }

def benchmark_decision_pipeline(num_hosts=10000):
    store = TrustStore()
    engine = PolicyEngine()
    ips = [f"10.0.{(i // 256) % 256}.{i % 256}" for i in range(min(num_hosts, 5000))]
    
    start_time = time.perf_counter()
    decisions = {}
    for ip in ips:
        score = store.get(ip)
        action = engine.evaluate(score)
        decisions[ip] = action
    end_time = time.perf_counter()
    
    total_time_ms = (end_time - start_time) * 1000
    avg_pipeline_us = (total_time_ms * 1000) / len(ips)
    
    return {
        'num_hosts': len(ips),
        'total_time_ms': round(total_time_ms, 2),
        'avg_pipeline_us': round(avg_pipeline_us, 4),
        'rate_hosts_per_sec': int(len(ips) / (end_time - start_time))
    }

def main():
    print("=" * 60)
    print("      ADG Performance & Scaling Benchmark Suite")
    print("=" * 60)
    
    print("\n[1/3] Benchmarking Policy Engine Evaluation Throughput...")
    policy_res = benchmark_policy_engine_throughput(200000)
    print(f"  - Operations Evaluated: {policy_res['iterations']:,}")
    print(f"  - Total Execution Time: {policy_res['total_time_ms']} ms")
    print(f"  - Average Latency per Evaluation: {policy_res['avg_latency_us']} µs")
    print(f"  - Evaluation Throughput: {policy_res['throughput_ops_sec']:,} ops/sec")
    
    print("\n[2/3] Benchmarking TrustStore BPF Map Lookup Latency...")
    lookup_res = benchmark_trust_lookup_scaling(5000)
    print(f"  - Simulated Hosts Checked: {lookup_res['num_hosts']:,}")
    print(f"  - Total Execution Time: {lookup_res['total_time_ms']} ms")
    print(f"  - Average Lookup Latency: {lookup_res['avg_lookup_us']} µs")
    
    print("\n[3/3] Benchmarking End-to-End Control Plane Decision Pipeline...")
    pipeline_res = benchmark_decision_pipeline(5000)
    print(f"  - Hosts Evaluated: {pipeline_res['num_hosts']:,}")
    print(f"  - Total Pipeline Time: {pipeline_res['total_time_ms']} ms")
    print(f"  - Average Pipeline Latency per Host: {pipeline_res['avg_pipeline_us']} µs")
    print(f"  - Decision Processing Rate: {pipeline_res['rate_hosts_per_sec']:,} hosts/sec")
    
    # Save results summary to CSV for paper inclusion
    summary_df = pd.DataFrame([
        {'Metric': 'Policy Engine Latency', 'Value': f"{policy_res['avg_latency_us']} µs", 'Unit': 'µs/op'},
        {'Metric': 'Policy Evaluation Throughput', 'Value': f"{policy_res['throughput_ops_sec']:,}", 'Unit': 'ops/sec'},
        {'Metric': 'TrustStore Lookup Latency', 'Value': f"{lookup_res['avg_lookup_us']} µs", 'Unit': 'µs/lookup'},
        {'Metric': 'Control Pipeline Processing Rate', 'Value': f"{pipeline_res['rate_hosts_per_sec']:,}", 'Unit': 'hosts/sec'}
    ])
    summary_df.to_csv('results/benchmark_summary.csv', index=False)
    print("\nSaved performance benchmark summary to results/benchmark_summary.csv")
    print("=" * 60)

if __name__ == "__main__":
    main()
