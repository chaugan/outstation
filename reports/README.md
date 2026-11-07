# Reports

Benchmark results and fidelity case studies from outstation runs. Each report is distilled from the analyzer's JSON output and records what the tool did on a real run.

## Index

| Date | Report | One line |
|---|---|---|
| 2026-11-05 | [Scale benchmark: 200 to 800 IEC 104 sessions on one host](2026-11-05-scale-benchmark.md) | As fast as possible on a 12-thread desktop: about 700 k I-frames/s for 200 masters, 240 k for 200 RTUs; CPU, memory, fds, setup cost per session, 800-session behaviour; gateway mode with an egress NIC does not work in master role. |
| 2026-04-17 | [165-RTU IEC 104 fleet replay: fidelity and scale demonstration](2026-04-17-fleet-replay-showcase.md) | 165 RTUs in slave role at original timing; 151,068 I-frames delivered in 3 min 43 s (about 680 I-frames/s) on a 12 vCPU / 12 GB VM. |

## Caveats on the 2026-04-17 report

- **It measures the captured pace, not a ceiling.** The run used original-timing pacing, so about 680 I-frames/s is the rate of the source capture. For as-fast-as-possible numbers see the [2026-11-05 scale benchmark](2026-11-05-scale-benchmark.md).
- **It predates the current engine and analyzer.** The link engine (t1/t2/t3, sequence checks, live GI/CI answers) and the analyzer (content-based score, verdict dimensions) were rewritten after it. At the time, `all_correct` rested on type-ID matches plus byte-identical counts. The analyzer did not check k/w windows, t1/t2/t3 timers or session close, although §7 of the report lists them as conditions of `all_correct`.
- **The run should be repeated** with the current version before its numbers are cited as current.

New reports should state the version or commit, the host (vCPU, RAM), the role, the pacing, the number of sessions, and CPU and memory use next to the message rate.
