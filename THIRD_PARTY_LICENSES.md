# Third-Party Licenses

| Component | License | Notes |
|---|---|---|
| Linux kernel (CAKE, NetEm qdiscs) | GPLv2 | Used via `tc`/`iproute2` CLI; no kernel source modified beyond enabling existing config options |
| iproute2 | GPLv2 | System package, used as-is |
| XGBoost | Apache 2.0 | `pip install xgboost` |
| scikit-learn | BSD-3-Clause | `pip install scikit-learn` |
| pandas, numpy | BSD-3-Clause | `pip install pandas numpy` |
| FastAPI | MIT | `pip install fastapi` |
| Laya | Apache 2.0 | `pip install laya`; model weights downloaded from Hugging Face (convaiinnovations/laya) |
| PyTorch | BSD-3-Clause | CPU-only build, dependency of Laya |
| scapy | GPLv2 | `pip install scapy`, used for packet feature extraction |
| Chart.js | MIT | Loaded via CDN in dashboard HTML |
| iperf3 | BSD-3-Clause (variant) | System package, used as traffic generator/measurement tool |
| nftables (nft) | GPLv2 | System package, used as-is by `halo/enforcer.py` for flow/device marks and intent sets |
| Prometheus | Apache 2.0 | `/metrics` uses the Prometheus text exposition format; server is optional and not redistributed |
| Grafana | AGPLv3 | Optional dashboard for the Prometheus metrics; not redistributed |
| irtt | GPLv2 | Optional isochronous round-trip measurement tool; not redistributed |
| pytest | MIT | Test runner (`tests_halo/`) |
| Hypothesis | MPL 2.0 | Property-based tests (`tests_halo/`) |

No proprietary code, data, or media is redistributed in this repository.

## Added for HALO-Walk (analysis, API runtime, emulation platform)

| Component | License | Notes |
|---|---|---|
| matplotlib | Matplotlib License (PSF-based, BSD-compatible) | Figures in `analysis/analyze.py`; not redistributed |
| SciPy | BSD-3-Clause | Mann-Whitney U in `analysis/analyze.py` |
| Uvicorn | BSD-3-Clause | ASGI server for `halo/api.py` |
| pydantic / Starlette | MIT / BSD-3-Clause | FastAPI dependencies |
| QEMU | GPLv2 | Software-emulated VM used to run the evidence matrix; system package, not redistributed |
| conntrack-tools | GPLv2 | `conntrack -L` flow accounting in `halo/controller.py`; system package |
| Ubuntu linux-image / linux-modules-extra 6.8.0-149 | GPLv2 | Kernel with sch_cake / sch_netem / act_ctinfo used inside the VM; downloaded from the Ubuntu archive, not redistributed |

Datasets: all traffic is generated synthetically by `halo/gen.py` (random payload bytes, no third-party media or captures).
No credentials are stored in the repository; `.env.example` contains only the fictitious `HALO_API_TOKEN=EXAMPLE-NOT-A-SECRET-0000`.
