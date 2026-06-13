# eBPF Adaptive Agent — Technical Diagrams

Mermaid sources for the host agent (`host/ebpf-agent`). Render in GitHub, GitLab, or any Mermaid-capable viewer.

---

## 1. System context

```mermaid
flowchart TB
    subgraph Host["Linux host"]
        subgraph Kernel["Kernel space"]
            TP["15 tracepoint programs\nexecve, connect, ptrace,\nopen/openat/openat2, write,\nsetuid/setgid, fork, exit,\nbind, sendto, capset, oom"]
            RB["RingBuf map\n72-byte header +\noptional exec filename"]
            DROPS["ringbuf_drops map"]
            TP --> RB
            TP --> DROPS
        end

        subgraph Agent["ebpf-agent userspace"]
            RC["RingBuf consumer"]
            EN["Enricher\nexec filename in-kernel,\nPID LRU, UID, cgroup"]
            MT["MITRE mapper + kill-chain\nMitreTags, ppid lineage"]
            AG["Aggregator\n1-min windows"]
            BL["Baseline engine\n168 seasonal buckets + EWMA"]
            ST[("SQLite\nbaseline.db v2")]
            PH["Phase manager\nlearning / monitoring"]
            SC["Scorer\nz-score / MAD, cold-start"]
            OTEL["OTel exporter\nLogRecords, spans, metrics"]
        end

        RB --> RC --> EN --> MT --> AG
        AG --> PH
        PH --> SC
        SC -->|"non-anomalous only"| BL
        BL <--> ST
        EN -->|"high-value events"| OTEL
        SC -->|"anomalies"| OTEL
        MT -->|"kill-chain"| OTEL
    end

    J["journald\nANOMALY, COLD-START, ENRICH-FAIL"]
    HM["HTTP :9110 /metrics\nhealth gauges only"]
    COL["OTel Collector\nOTLP gRPC"]

    SC --> J
    PH --> HM
    OTEL --> COL
```

---

## 2. Event path (detection pipeline)

```mermaid
flowchart LR
    A["Syscall fires"] --> B["BPF: ringbuf record\npid, ppid, uid, cgroup, comm, flags"]
    B --> C["Go: parse 72B header +\noptional exec filename"]
    C --> D["Enrich: in-kernel path for exec,\n/proc LRU for others, passwd, cgroup"]
    D --> E["MITRE: technique IDs + kill-chain observe"]
    E --> F["Aggregate: dimension keys\nper user / comm / container"]
    F --> G["Window tick: rotate 1m"]
    G --> H{"Monitoring phase?"}
    H -->|no| I["Ingest into baseline"]
    H -->|yes| J["Score vs baseline first"]
    J --> K["Log + OTel export anomalies"]
    J --> L["Ingest non-anomalous dimensions only"]
    I --> G
    L --> G
```

---

## 3. Two-phase lifecycle

```mermaid
flowchart TB
    START([Agent start]) --> L["Phase 1: Learning"]
    L --> L1["Each window: ingest into baseline"]
    L1 --> L2{"learning_duration elapsed?"}
    L2 -->|no| L1
    L2 -->|yes| M["Phase 2: Monitoring"]
    M --> M1["Per window: score first,\ningest non-anomalous only,\nlog + OTel anomalies"]
    M1 --> M
    M --> R["Reset / reconfigure"]
    R --> L
```

---

## 4. Telemetry split (current implementation)

```mermaid
flowchart TB
    subgraph Detection["Detection output"]
        LOG["Structured text logs\njournald"]
        OTEL["OTLP to collector\nLogRecords, anomaly spans,\nkill-chain spans, metrics"]
    end

    subgraph Health["Operational health"]
        PROM["Prometheus scrape\nlocalhost:9110/metrics"]
    end

    Agent["ebpf-agent"] --> LOG
    Agent --> OTEL
    Agent --> PROM
```

---

## 5. Config and BPF attachment

```mermaid
flowchart LR
    CFG["config.yaml\ntracepoints + baseline + scoring"] --> LOAD["config.Load"]
    LOAD --> SPEC["Load BPF object\nembed exec.bpf.o"]
    SPEC --> ATTACH["Attach each tracepoint\nto listed program"]
    ATTACH --> RUN["Main loop:\nringbuf + window ticker + health ticker"]
```
