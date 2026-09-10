# PS-26145 Real Execution Performance Benchmark

- **Timestamp**: 2026-09-10T07:08:00Z
- **Platform**: win32
- **Python**: 3.13.7
- **Peak Pipeline Throughput**: 605.24 flows/sec
- **Average P50 Latency**: 2.1102 ms
- **Average P95 Latency**: 2.2966 ms
- **Total Flows Evaluated**: 16000
- **Total Alerts Emitted**: 16000

## Detailed Batch Metrics

| Batch Scale | Throughput (flows/s) | Mean Latency (ms) | P50 (ms) | P95 (ms) | P99 (ms) | Alerts | Error Rate |
|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| 1000 flows | 605.24 | 1.6515 | 1.6515 | 1.6721 | 1.6721 | 1000 | 0.0% |
| 5000 flows | 528.02 | 1.8930 | 1.9282 | 2.0819 | 2.0819 | 5000 | 0.0% |
| 10000 flows | 368.18 | 2.7151 | 2.7508 | 3.1359 | 3.2090 | 10000 | 0.0% |
