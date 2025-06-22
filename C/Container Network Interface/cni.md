🧱 Term: Container Network Interface (CNI) — Web3 / Smart Contract Security & DevOps Context
Container Network Interface (CNI) is a specification and plugin system that defines how container runtimes (like Docker, containerd, or Kubernetes) configure network interfaces inside containers. In a Web3 context, CNIs are essential for:

🧩 Deploying decentralized infrastructure like validators, bridges, rollup nodes, sequencers, relayers, and oracles
🔐 Securing containerized smart contract infrastructure
⚡ Enabling secure, modular, observable, and scalable networking for blockchain microservices

📘 1. Types of CNI Plugins Used in Web3 DevOps
CNI Plugin Type	Description
Bridge	Default Docker-style local bridge between containers and host
Calico	Layer 3 CNI with built-in network policy enforcement, used in secure K8s
Flannel	Lightweight Layer 2 overlay CNI — simple setup, popular for devnets
Cilium	eBPF-powered CNI with deep observability and API-aware firewalling
Multus	Allows multiple CNIs per pod — useful for separate control/data planes

💥 2. Attack Surfaces from Misconfigured CNIs in Web3 Infrastructure
CNI Misuse or Misconfig	Risk Introduced
Open Pod Networking	Bridge nodes or validators may expose RPC/gRPC externally
Lack of Egress Policy	Malicious container can exfiltrate data or ping critical endpoints
Shared Network Namespace	One compromised service sees all container traffic
Ingress Spoofing	Fake validator joins using forged IP without whitelisting enforcement
CNI Plugin Drift	Outdated CNI leads to security holes or incompatibility with container runtimes

🛡️ 3. Best Practices for Secure CNI Usage in Web3
Strategy	DevOps Implementation
✅ Use Policy-Aware CNIs (e.g., Calico/Cilium)	Enforce traffic rules per pod/workload
✅ Define NetworkPolicy in K8s	Allow only specific cross-pod communication
✅ Isolate RPC/Gateway Containers	No direct access from external unless explicitly allowed
✅ Use Multus for Network Isolation	Separate control plane (relayer, prover) from data plane (user RPCs)
✅ Log Network Flows	Capture and analyze flows for anomalies or drift detection

✅ 4. Code: Example Kubernetes NetworkPolicy for a Web3 Validator Pod
This Kubernetes YAML ensures:

Validator pod only accepts connections from known ingress

Denies all egress unless explicitly allowed

Applies PodSelector and namespace scoping

