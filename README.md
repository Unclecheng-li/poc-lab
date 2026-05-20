# poc-lab

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

Directories are organized by **CVE identifier** (e.g. `CVE-2026-31431/`). When a vulnerability has no assigned CVE, use its public name (e.g. `RedSun/`, `YellowKey/`).

Browse the repository root to see all available PoCs — the list grows as new vulnerabilities are disclosed and reproduced.

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

## Related

- [VulnClaw](https://github.com/Unclecheng-li/VulnClaw) — AI-powered penetration testing framework

## License

MIT
