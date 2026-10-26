# php2shell Patch Analysis — What's Fixed, What's Not

**Patch:** [Commit 3584a98bda](https://github.com/php/php-src/commit/3584a98bda) — 300 files  
**Fixed versions:** PHP 8.2.35, 8.3.36, 8.4.27, 8.5.12  
**Author:** Qi Deng (@ikow) — 2026-10-21

---

## What the Patch Fixes

### OOM Handling Rewrite (CVE-2026-109618)

The `longjmp()`-based OOM handler is replaced with a two-tier approach:

- **Soft OOM:** Error stored in `EG(delayed_oom)`, raised at the next VM safe point via `zend_handle_delayed_oom()`. Throws `UnwindExit` when a userland frame exists.
- **Hard OOM:** `_exit(137)` — no bailout, no recovery. Triggered above a configurable threshold.

This eliminates the stale `EG()` state problem: cleanup always runs before memory is freed.

### Early Global Reset (CVE-2026-109619)

`php_basic_early_rinit()` is called from `php_request_startup()` right after `zend_activate()`. It zeroes:
- `BG(serialize)`
- `BG(unserialize)` 
- `BG(serialize_lock)`

This runs **before** rfc1867 multipart parsing, closing the stale-BG window.

### rfc1867 Hardening

New `in_rfc1867_update` flag forces `__PHP_Incomplete_Class` for all deserialized objects during upload progress handling. No `__wakeup`, `__unserialize`, `__destruct`, or autoloading fires.

---

## What the Patch Does NOT Fix

### 1. Chain A Still Works on Patched PHP ⚠️

**Confirmed on PHP 8.5.12** by [independent researcher](https://dev.to/tanahiro2010/investigating-the-return-of-the-php2shell-nightmare-eee).

The upload_progress write primitive is a feature, not a bug. Filenames are still stored raw in session files. Combined with any LFI vulnerability, this gives RCE — even on fully patched PHP.

**Why:** The patch fixes OOM corruption and stale state. It does not sanitize filenames stored by `session.upload_progress`.

### 2. `session.upload_progress.enabled=Off` is Insufficient ⚠️

[PHP core developer confirmed](https://daubois.dev/blog/cve-2026-109618-php2shell-rumors/): "Do not apply the session flag as a fix for CVE-2026-109618."

CVE-2026-109618 (OOM corruption) does not require `session.upload_progress` at all. Any oversized multipart POST triggers the OOM path. The setting only covers CVE-2026-109619 session paths.

### 3. PS(serializer) Leak Not Fixed in This Patch

The `PS(serializer)` is NOT reset in `RSHUTDOWN` or early RINIT by commit 3584a98. The Chain C handler mismatch (serializer leak across FPM requests) is addressed by [PR #22113](https://github.com/php/php-src/pull/22113) separately.

**Impact:** If a deployment applies the OOM patch but not PR #22113, the handler mismatch chain still works.

### 4. Session Fixation Not Fixed in This Patch

The `use_only_cookies` check bypass in the rfc1867 handler is fixed by PR #22113, not commit 3584a98. Session ID injection via POST body still works without PR #22113.

### 5. var_destroy UAF Partially Addressed

The `in_rfc1867_update` flag prevents real object instantiation during upload progress (blocks rfc1867 exploitation). But the core Phase 1/Phase 2 ordering in `var_destroy` (free chunks then fire `__destruct`) is unchanged. User-code `unserialize()` on controlled input may still trigger the UAF.

### 6. `zend_bailout()` Still Used as Fallback

When `execute_data == NULL` (no active PHP frame — certain startup paths), `zend_handle_delayed_oom()` falls back to `zend_bailout()` (the old longjmp). The `in_rfc1867_update` + `__PHP_Incomplete_Class` mitigates exploitation here, but stale-state for non-session globals isn't fully eliminated.

### 7. CVE-2026-109619 Has Three Arms, Not Just session.upload_progress

[JFrog analysis](https://research.jfrog.com/post/php2shell-all-you-need-to-know-about-cve-2026-109618-and-cve-2026-109619/) identifies additional persistent variables affected:

| Arm | PHP Versions | Mitigation |
|-----|-------------|-----------|
| `session.upload_progress` | All affected | `session.upload_progress.enabled=Off` |
| `fatal_error_backtraces` | **8.5.x only** | `fatal_error_backtraces=0` |
| OPcache shared memory | All with OPcache | No INI setting — patch required |

### 8. PHP 8.4 `request_parse_body()` Widens Attack Surface

PHP 8.4 introduced `request_parse_body()` which parses `multipart/form-data` on **non-POST methods** (GET, PUT, PATCH, DELETE). POST-only WAF rules are bypassed.

[Source](https://thehackernews.com/2026/10/php2shell-what-actually-protects-you.html)

### 9. EOL PHP Has No Official Fix

| Branch | Status |
|--------|--------|
| 8.2–8.5 | Official patches available |
| 8.0–8.1 | EOL — [community backports](https://github.com/Anton-Barinov/php2shell-patches) exist (unofficial) |
| 5.x–7.x | No fix, no backport |

---

## Counterintuitive Mitigations

### `memory_limit=-1` Is Actually Helpful

Removing the memory limit removes the **predictable allocation failure** the attacker needs for the OOM trigger. Without a memory limit, PHP allocates until the OS kills the process — which is a different (and harder to exploit) failure mode.

**Warning:** Do NOT substitute `RLIMIT_AS` or `RLIMIT_DATA` — these cause `mmap()` failures that trigger the same vulnerable path.

### `pm.max_requests=1` Breaks Chain E

Setting FPM workers to die after each request prevents the stale-state consumer from hitting the same worker. But this has significant performance impact.

---

## Summary: Defense in Depth

| Measure | Chains Blocked | Note |
|---------|---------------|------|
| Patch to 8.2.35+ | All core bugs | **The only complete fix** |
| PR #22113 | Session fixation, serializer leak | Separate from OOM patch |
| `session.upload_progress.enabled=Off` | CVE-2026-109619 session paths only | Does NOT fix CVE-2026-109618 |
| `fatal_error_backtraces=0` (8.5.x) | CVE-2026-109619 backtrace arm | PHP 8.5 specific |
| `memory_limit=-1` | CVE-2026-109618 OOM trigger | Counterintuitive but effective |
| `pm.max_requests=1` | Chain E stale state | Performance cost |
| Block multipart POST at edge | All chains | Breaks file uploads |
| Fix application LFI sinks | Chain A | Chain A works even on patched PHP |

---

## References

- [JFrog — Full technical analysis](https://research.jfrog.com/post/php2shell-all-you-need-to-know-about-cve-2026-109618-and-cve-2026-109619/)
- [PHP core dev — INI won't save you](https://daubois.dev/blog/cve-2026-109618-php2shell-rumors/)
- [Dev.to — Chain A still works on 8.5.12](https://dev.to/tanahiro2010/investigating-the-return-of-the-php2shell-nightmare-eee)
- [The Hacker News — What actually protects you](https://thehackernews.com/2026/10/php2shell-what-actually-protects-you.html)
- [Wiz — Downstream impact](https://www.wiz.io/blog/php2shell-php-rce)
- [Penligent — Patch mechanics](https://www.penligent.ai/hackinglabs/php2shell/)
