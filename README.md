# Real-Time Web Application Threat Detection & SOC Lab

A hands-on Purple Team lab demonstrating end-to-end web attack detection, log telemetry pipeline engineering, and SIEM event correlation using **Wazuh (SIEM/XDR)**, **Docker**, and a lightweight custom PHP web server.

---

[ Attacker / Scripts ]
│ (HTTP Requests: SQLi, XSS, Recon)
▼
┌───────────────────────────────────────────────────────────┐
│ Host System (Windows)                                     │
│  ├── PHP Server (:8000) ──▶ Generates access.log          │
│  │                         (Apache Combined Format)       │
│  │                                   │                     │
│  └── Wazuh Agent (WazuhSvc) ─────────┘                     │
│         │ (Encrypted Syslog/TCP :1514)                     │
└─────────┼─────────────────────────────────────────────────┘
▼
┌───────────────────────────────────────────────────────────┐
│ Docker Containers (Wazuh Single-Node Cluster)             │
│  ├── wazuh.manager   (Decoders & Detection Engine)        │
│  ├── wazuh.indexer   (OpenSearch Log Store)               │
│  └── wazuh.dashboard (Kibana-based Visual UI :443)        │
