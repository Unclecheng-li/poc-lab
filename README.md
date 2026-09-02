# poc-lab

**English** | [中文](./README.zh-CN.md)

> PoC & reproduction scripts for recently disclosed high-severity vulnerabilities.

Focused on **fresh, impactful CVEs** — Linux kernel, Windows, macOS, containers, services, and beyond.

## What's Inside

Each vulnerability directory follows a consistent layout:

| File | Purpose |
|------|---------|
| `exploit.py` / `exploit.sh` | PoC script |
| `README.md` | CVE info, affected versions, reproduction steps, references |

## Directory Structure

```
poc-lab/
├── CVE-2026-XXXXX/       # One directory per CVE
│   ├── exploit
|   ├── build
│   └── README.md
├── VULN-NAME/            # Or by vulnerability name if no CVE assigned
│   ├── exploit.sh
│   └── README.md
└── ...
```

Vulnerability directories are grouped into **topic categories** at the repo root; each category folder ships an index `README.md`. Individual directories keep CVE-first naming (e.g. `CVE-2026-31431/`), or a public name when no CVE was assigned.

| Category | Contents |
|----------|----------|
| `DeepSeek Harness/` | DeepSeek Harness (AI agent framework) series (6) |
| `Linux Kernel/` | Linux kernel LPE / escapes / DoS (14) |
| `Web Applications/` | Web apps / panels / CMS (3) |
| `Databases/` | Databases / KV stores (2) |
| `Web Servers & Protocols/` | Web servers & network protocols (2) |
| `Browsers/` | Chrome / Firefox browsers (2) |
| `AI Infrastructure/` | AI infrastructure (1) |
| `Desktop & Client Apps/` | Desktop / client apps & media libs (2) |

Browse each category folder to see all available PoCs — the list grows as new vulnerabilities are disclosed and reproduced.

## Quick Start

```bash
# Clone
git clone https://github.com/Unclecheng-li/poc-lab.git
cd poc-lab

# Pick a vulnerability directory
cd <CVE-or-NAME>

# Read the reproduction guide first
cat README.md

# Run the PoC
python3 exploit.py   # or: bash exploit.sh
```

## Contributing

PoC additions are welcome. To add a new vulnerability:

1. Create a directory named after the CVE or vulnerability name
2. Include the PoC script (`exploit.py` / `exploit.sh`) and a `README.md` with:
   - CVE identifier & vulnerability name
   - Affected versions / components
   - Step-by-step reproduction guide
   - References (advisory links, patch commits, credits)
3. Open a Pull Request

## Disclaimer

This repository is for **security research and educational purposes only**.

- Do NOT use these PoCs against systems you don't own or lack authorization to test.
- The author assumes no liability for misuse.
- Always follow responsible disclosure practices.

## Links

- [VulnClaw](https://github.com/Unclecheng-li/VulnClaw) — AI-powered penetration testing framework

## License

MIT
