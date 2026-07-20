# ntptool

A comprehensive, cross-platform **NTP server testing toolkit** written in modern
C++17. A single self-contained CLI that bundles a whole collection of tools for
querying, measuring, comparing, monitoring, tracing and security-auditing NTP
servers — for Windows and Linux, with no external dependencies.

```
ntptool query   pool.ntp.org -c 8
ntptool compare 0.pool.ntp.org time.google.com time.cloudflare.com
ntptool monitor time.example.com -i 2
ntptool scan    192.0.2.0/28 --file targets.txt -j 64
ntptool control time.example.com --list
ntptool security ntp.example.net
ntptool trace   2.pool.ntp.org
```

---

## Features

| Command    | What it does |
|------------|--------------|
| `query`    | Measures clock **offset**, round-trip **delay** and quality metrics over N samples, with full statistics (min/avg/median/max, stddev, jitter). |
| `monitor`  | Continuously polls one server, printing a live line per poll with a rolling average/jitter and a final summary. |
| `compare`  | Queries several servers side-by-side, computes a **consensus offset** and flags **outliers / falsetickers**. |
| `scan`     | Multi-threaded sweep of many hosts / IPs / **IPv4 CIDR ranges** to discover reachable NTP servers. |
| `control`  | Reads **mode-6** system and peer variables and enumerates associations (ntpq-style). |
| `security` | Audits a server: sync state, Kiss-o'-Death, and amplification vectors — classic **mode-7 monlist (CVE-2013-5211)** and **mode-6 readvar** reflection, with measured amplification factors. |
| `trace`    | Follows a server's reference-id chain **upstream toward stratum 1**. |
| `selftest` | Known-answer tests for MD5, SHA-1 and the NTP timestamp math. |

Additional capabilities:

- **Full RFC 5905 measurement** — the four-timestamp model (T1–T4), offset
  `θ = ((T2−T1)+(T3−T4))/2`, delay `δ = (T4−T1)−(T3−T2)`, root delay/dispersion/
  distance, precision, poll and leap-indicator decoding.
- **Anti-spoofing** — validates the origin-timestamp echo and the server mode;
  rejects bogus packets.
- **Kiss-o'-Death** handling (RATE / DENY / RSTR …).
- **Symmetric-key authentication** (MD5 and SHA-1 keyed MACs) for both sending
  authenticated requests and verifying authenticated replies.
- **IPv4 and IPv6**, with `-4` / `-6` forcing and automatic selection.
- **Three output formats** — human-readable `text`, `json` and `csv` — for every
  command, so results plug straight into scripts and dashboards.
- **Zero dependencies** — only the C++ standard library and the OS socket API.

---

## Building

Requirements: a C++17 compiler and CMake ≥ 3.15.

### Linux / macOS

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
./build/bin/ntptool selftest
```

### Windows (MSVC)

From a *Developer Command Prompt* (or after running `vcvars64.bat`):

```bat
cmake -S . -B build -G "NMake Makefiles" -DCMAKE_BUILD_TYPE=Release
cmake --build build
build\bin\ntptool.exe selftest
```

Or generate a Visual Studio solution:

```bat
cmake -S . -B build -G "Visual Studio 17 2022"
cmake --build build --config Release
```

### Windows (MinGW / GCC)

```bash
cmake -S . -B build -G "Ninja" -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

The resulting binary is `build/bin/ntptool[.exe]`.

---

## Usage

```
ntptool <command> [options] [host ...]
ntptool <host>                 # shorthand for: ntptool query <host>
```

### Global options

| Option | Description |
|--------|-------------|
| `-p, --port <n>` | UDP port (default `123`) |
| `-4, --ipv4` / `-6, --ipv6` | Force IPv4 or IPv6 |
| `-t, --timeout <ms>` | Receive timeout per query (default `2000`) |
| `-r, --retries <n>` | Retries after a timeout (default `0`) |
| `-c, --count <n>` | Samples / polls (`0` = infinite where allowed) |
| `-i, --interval <sec>` | Delay between samples (default `1.0`) |
| `--ntp-version <n>` | NTP protocol version 1–4 (default `4`) |
| `-f, --format <fmt>` | `text` \| `json` \| `csv` |
| `--color` / `--no-color` | Force / disable ANSI colours (auto-detects a TTY) |
| `-v, --verbose` | More detail; repeat (`-v -v`) for a raw hexdump |
| `--auth <md5\|sha1>` | Symmetric-key auth (with `--key` / `--key-id`) |
| `--key <secret>` | Authentication key (ASCII) |
| `--key-id <n>` | Authentication key identifier |
| `-h, --help` | Help (`ntptool help <command>` for details) |

---

## Examples

**Measure a server with 8 samples:**

```
$ ntptool query time.example.com -c 8
== time.example.com ==  (203.0.113.10:123)
  [1] offset=+5.632 ms  delay=20.493 ms  stratum=3
  ...
  offset  min/avg/median/max = 4.984 / 5.860 / 5.754 / 6.950 ms
          stddev 0.818 ms, jitter 1.301 ms
  delay   min/avg/median/max = 19.627 / 21.247 / 20.789 / 23.781 ms
  packet loss: 0/8
```

**Compare servers and spot outliers:**

```
$ ntptool compare time.google.com time.cloudflare.com pool.ntp.org -c 5
Comparing 3 servers (5 samples each). Consensus offset: +0.412 ms
  HOST                 ADDRESS            STR  OFFSET(ms)  DELAY(ms)  JIT(ms)  LOSS
  time.cloudflare.com  ...                  3      +0.318      8.021    0.104   0/5
  time.google.com      ...                  1      +0.503      9.144    0.087   0/5
  ...
```

**Continuous monitoring (Ctrl-C to stop):**

```
$ ntptool monitor time.example.com -i 2
[12:03:35] #1  offset=+5.476 ms  delay=20.547 ms  str=3  [avg 5.476 jit 0.000 ms]
...
```

**Discover NTP servers on a subnet:**

```
$ ntptool scan 192.0.2.0/28 -j 64 -t 800 -f csv
target,address,reachable,stratum,refid,offset_ms,delay_ms,error
192.0.2.1,192.0.2.1:123,1,2,198.51.100.9,-0.204,3.517,
...
```

**Read mode-6 variables (ntpq-style):**

```
$ ntptool control time.example.com            # system variables
$ ntptool control time.example.com --list      # associations (peers)
$ ntptool control time.example.com --assoc 12345 --vars offset,jitter,delay
```

**Security audit:**

```
$ ntptool security ntp.example.net
  [ OK ] reachability: stratum 2, refid 198.51.100.9, offset +0.204 ms
  [ OK ] sync-state: synchronised, leap=no-warning
  [ OK ] monlist: mode-7 monlist disabled / not answered (good)
  [ OK ] mode6-readvar: mode-6 queries restricted / not answered (good)
  Overall: no amplification vectors detected.
```

**Authenticated query:**

```
$ ntptool query ntp.internal --auth md5 --key-id 1 --key "s3cr3t"
```

---

## Output formats

Every command supports `-f text|json|csv`:

- **text** — coloured, human-readable (colours auto-disable when piped).
- **json** — structured objects/arrays; ideal for `jq` and automation.
- **csv** — one header row plus one row per sample/host/finding.

```bash
ntptool query time.example.com -c 20 -f json | jq '.[0].statistics.offset_ms.median'
ntptool scan --file targets.txt -f csv > results.csv
ntptool security ntp.example.net -f json | jq '.high'
```

Exit codes: `0` success, `1` measurement/health failure (no response, or a HIGH
security finding), `2` usage error, `3` fatal init error.

---

## How the measurement works

Each query records four timestamps:

```
 T1  client transmit     (originate)
 T2  server receive
 T3  server transmit
 T4  client receive      (destination)

 offset θ = ((T2 − T1) + (T3 − T4)) / 2
 delay  δ = (T4 − T1) − (T3 − T2)
```

Timestamps are 64-bit NTP fixed-point values (seconds since 1900 + a 32-bit
fraction). All differences are computed in the wrapping 64-bit domain and then
reinterpreted as signed, which keeps them correct across an era boundary for any
realistic measurement delta.

---

## Project layout

```
include/ntptool/   Public headers (time, packet, socket, client, stats,
                   control, md5/sha1, output, cli)
src/               Implementations
src/commands/      One file per subcommand
CMakeLists.txt     Build (Windows + Linux)
targets.example.txt  Sample target list for `scan --file`
```

---

## Notes & responsible use

- `security` sends the classic monlist and mode-6 probes used by real scanners.
  **Only run it against servers you are authorised to test.** A well-configured
  server returns nothing to these probes — that is the desired result.
- Many public servers rate-limit or restrict mode-6/mode-7; a timeout there is
  expected and usually means the server is correctly hardened.
- Corporate networks frequently block outbound UDP/123 except to internal time
  servers; if every query times out, check firewall egress rules.

---

## License

MIT — see [LICENSE](LICENSE).
