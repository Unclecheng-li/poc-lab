<div align="center">

<h1>poc-lab</h1>

<p><strong>PoC &amp; reproduction lab for recent high-severity vulnerabilities</strong> — Linux kernel · KVM · web apps · databases · browsers · AI infrastructure</p>

<p>Every vulnerability ships as one reproducible chain: root cause → PoC → fix.</p>

<p>
  <a href="https://github.com/Unclecheng-li/poc-lab/stargazers"><img src="https://img.shields.io/github/stars/Unclecheng-li/poc-lab?style=social" alt="Stars"></a>
  <a href="https://github.com/Unclecheng-li/poc-lab/forks"><img src="https://img.shields.io/github/forks/Unclecheng-li/poc-lab?style=social" alt="Forks"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/Unclecheng-li/poc-lab?color=blue" alt="License"></a>
  <img src="https://img.shields.io/badge/PoCs-32-2ea44f" alt="PoCs">
  <img src="https://img.shields.io/badge/Linux%20Kernel-LPE%20Series-CC0000" alt="Linux Kernel LPE Series">
</p>

**简体中文**: [`README.md`](README.md)

</div>

---

> ## Quick Start
>
> ```bash
> git clone https://github.com/Unclecheng-li/poc-lab.git && cd poc-lab
> cd "Linux Kernel"                 # pick a category
> cat "CVE-2026-31431 Copy Fail"/README.md   # read the write-up first
> python3 "CVE-2026-31431 Copy Fail"/exploit/exp.py   # then run the PoC
> ```

---

## What is poc-lab?

A PoC &amp; reproduction repository that groups high-severity vulnerabilities by **topic category**. Each CVE is sourced from security advisories and public disclosures (NVD / vendor bulletins / QiAnXin QVD, etc.) and ships with a complete Chinese write-up: root cause, exploit chain, PoC and fix — ready for fast reproduction, code auditing and further research.

### Repository layout

```
poc-lab/
├── DeepSeek Harness/            # DSH AI agent framework series (6)
├── Linux Kernel/                # Linux kernel (14)
│   ├── Dirty-style page-cache LPE # CopyFail / DirtyFrag / DirtyCBC / ...
│   ├── Standalone LPE · heap     # PinTheft / GhostLock / CIFSwitch / ...
│   └── KVM virtualization escape # Januscape / Zapscape
├── Web Applications/            # Web panels / CMS / apps (3)
├── Databases/                   # Databases / KV stores (2)
├── Web Servers & Protocols/     # Web servers & network protocols (2)
├── Browsers/                    # Chrome / Firefox browsers (2)
├── AI Infrastructure/           # AI infrastructure (1)
├── Desktop & Client Apps/       # Desktop / client apps & media libs (2)
│
└── single vulnerability dir/    # see "Standard layout" below
    ├── README.md
    ├── exploit/
    ├── build/
    └── env/
```

### Category index

| Category | Count | Contents |
|----------|------:|----------|
| [`DeepSeek Harness/`](./DeepSeek%20Harness/README.md) | 6 | DeepSeek Harness (AI agent framework): config-load RCE / read-only sandbox leak / VM sandbox escape / chained escape RCE / Host-header unauth RCE / macOS LPE |
| [`Linux Kernel/`](./Linux%20Kernel/README.md) | 14 | Dirty-style page-cache LPE (CopyFail / Dirty Frag / DirtyCBC / DirtyDecrypt / Fragnesia / act_pedit), standalone LPE / heap (Slab Cross-Cache / PinTheft / GhostLock / CIFSwitch / SSH Keysign), KVM escapes (Januscape / Zapscape) |
| [`Web Applications/`](./Web%20Applications/README.md) | 3 | cPanel2Shell / Nezha Monitoring / wp2shell (WordPress) |
| [`Databases/`](./Databases/README.md) | 2 | Redis RESTORE RCE / Valkey RESP DoS |
| [`Web Servers & Protocols/`](./Web%20Servers%20%26%20Protocols/README.md) | 2 | NGINX Rift / HTTP2 Bomb |
| [`Browsers/`](./Browsers/README.md) | 2 | Chrome CSSFontFeatureValuesMap UAF / Firefox IonStack JIT |
| [`AI Infrastructure/`](./AI%20Infrastructure/README.md) | 1 | LiteLLM authorization-chain privilege escalation |
| [`Desktop & Client Apps/`](./Desktop%20%26%20Client%20Apps/README.md) | 2 | Notepad++ RCE / PixelSmash (FFmpeg MagicYUV) |

## Standard layout of each vulnerability directory

The repo follows a consistent "CopyFail template" — one directory per CVE, same structure:

| File / dir | Purpose |
|------------|---------|
| `README.md` | 11-section analysis: overview / affected range / root cause / exploit mechanism / PoC analysis / reproduction / fix / detection / timeline / references / disclaimer |
| `exploit/` | PoC scripts (`exp.py` / `exp.c` / `exp.html` / `lpe.sh` …) |
| `build/` | Compiled artifacts for kernel-class exploits |
| `env/` | `docker-compose.yml` reproduction environment for web-class exploits |

## Adding a new vulnerability

Newly disclosed CVEs follow a fixed pipeline:

1. Create a `<CVE-ID Name>/` directory following the CopyFail template;
2. Write `README.md` (the 11 sections above) + PoC under `exploit/` (prefer first-hand source links);
3. Push to remote `main`.

## Related projects

- [VulnClaw](https://github.com/Unclecheng-li/VulnClaw) — AI-driven penetration testing framework
- [DeepSec](https://github.com/Unclecheng-li/DeepSec) — AI security platform (Shield code audit + Spear authorized pentest)

## Disclaimer

This repository is for **security research and educational purposes only**.

- Do NOT run these PoCs against systems you don't own or lack authorization to test.
- The author assumes no liability for misuse.
- Always follow responsible disclosure practices.

## License

MIT
