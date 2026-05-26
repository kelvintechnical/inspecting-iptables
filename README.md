# Lab: Inspecting iptables — Default Chains and Rules

- **Series:** linux-ops-mastery — RHCSA Firewall
- **Subjects covered:** Netfilter mental model, `iptables` vs `nft`, listing rules with `iptables -L`, numeric and verbose modes, line numbers, alternate tables (`nat`, `mangle`), correlating `iptables-save` output with what `firewalld` programs on the backend
- **Career arcs covered:** RHCSA (legacy wording still says “iptables”; you must recognize the chains), RHCE (Ansible `ansible.posix.firewalld` still maps to the same kernel rules), SRE (incident triage: “is traffic dropped in INPUT or FORWARD?”), DevOps (debugging kube-proxy / CNI rulesets), AI/MLOps (understanding host firewall when exposing model APIs)
- **Prerequisite:** Basic shell navigation; awareness that RHEL 9 defaults to `firewalld` with an `nftables` backend
- **Time Estimate:** 30 to 45 minutes
- **Difficulty arc:** Task 1 baseline services · 2–3 classic `iptables -L` reading skills · 4 other tables and save-format · 5 counters and line numbers edge cases · 6 capstone plus cleanup

---

## Objective

Modern RHEL hosts rarely *configure* packet filtering with raw `iptables` anymore, but the **language of chains** — `INPUT`, `FORWARD`, `OUTPUT` — is still how engineers describe where a packet died. This lab builds the reflex to list rules, read verdict targets (`ACCEPT`, `DROP`, `REJECT`), and correlate human listings with the machine-oriented `iptables-save` format.

By the end you can answer: “Which chain would evaluate this SSH packet first?” and “Does `iptables -L` show me everything the kernel enforces?” (Spoiler: always pair listing with context about `firewalld` and `nft`.)

> **Lab safety note:** Tasks 1–5 are read-only. Task 6 writes a short report under `/tmp` and removes it in **Cleanup**. Do not run `iptables -F` on production systems unless you understand every management layer above Netfilter.

---

## Concept: iptables Is a Front Door to Netfilter Rules

The Linux kernel’s packet classifier historically exposed the **filter** table with three built-in chains:

```
                    ┌────────── netfilter decision path ──────────┐
   incoming packet  │                                           │
   from wire ───────►  PREROUTING (raw/mangle/nat)               │
                    │         │                                  │
                    │         ▼                                  │
                    │     routing decision                       │
                    │         │                                  │
                    │    local? ──yes──► INPUT  ──► local process │
                    │         │                                  │
                    │         no (forwarded)                     │
                    │         └──► FORWARD ──► POSTROUTING ───► wire
                    │                                           │
   locally generated│                                           │
   traffic ─────────► OUTPUT ──► ... ──► wire                   │
                    └───────────────────────────────────────────┘

`iptables -L` (default table: filter) shows the policy and rules
for INPUT / FORWARD / OUTPUT — the “first firewall vocabulary” every admin learns.
```

On RHEL 9, `/usr/sbin/iptables` is commonly the **nftables compatibility** front end (`iptables-nft`). The verbs you type are classic; the backend is modern.

> **Why this matters:** Interviewers and ticket descriptions still say “check iptables.” If you only know `firewall-cmd`, you can still be blind to duplicate or conflicting rules expressed through `nft`. Learning to *read* `iptables -L` keeps you fluent in three decades of documentation and scripts.

---

## 📜 Why iptables Exists — The Story

Long before application-level firewalls, administrators needed a way to say: **this packet may pass; this one must not.** The Linux kernel answered with **Netfilter**, a set of hooks inside the network stack where verdicts attach to traffic as it crosses the boundary between kernel and user space.

The `iptables` user-space tool became the everyday interface to program those hooks: tables (`filter`, `nat`, `mangle`, …), chains (`INPUT`, `FORWARD`, `OUTPUT`, …), and rules that match addresses, ports, interfaces, and connection state. Entire distributions were documented around `iptables-save` and `iptables-restore` because those formats were stable enough to check into revision control.

`firewalld` arrived to solve a different pain: **dynamic zones**, friendly service names, and reload semantics without rewriting entire tables by hand. Starting with **RHEL 7 and later**, `firewalld` is the supported default for workstation and server installs, and the underlying implementation moved toward **nftables**. That does not erase history: vendor hardening guides, container networking docs, and cloud images still drop you into `iptables` phrasing when they mean “kernel packet policy.”

The RHCSA candidate’s job is not to reject progress — it is to **read reality on the machine in front of you**. `iptables -L` remains a fast, universal lens for “what does the filter table look like right now?” even when another daemon owns the authoritative configuration.

> **The point of the story:** Names change (`iptables` → `nft`); hooks do not. Master the chains once, and every future tool is just a different editor for the same story.

---

## 👪 The iptables Family — Who Lives There

### By “what am I listing?”

| Command family | What you learn |
|---|---|
| `iptables -L` | Human-oriented listing for the **filter** table |
| `iptables -S` | Same rules in **restore/save** syntax (copy-paste friendly) |
| `iptables-save` | Entire ruleset snapshot (all tables the tool prints) |
| `iptables -t nat -L` | Address translation view (PREROUTING/POSTROUTING/OUTPUT) |

### By chain (filter table classics)

| Chain | Typical traffic | First question you ask |
|---|---|---|
| `INPUT` | Packets destined **to this host** | “Is SSH/httpd allowed to bind?” |
| `FORWARD` | Packets **routed through** the host | “Is this a router/NAT gateway?” |
| `OUTPUT` | Packets **originating locally** | “Can this host reach the API?” |

### By companion tools on RHEL 9

| Tool | Role |
|---|---|
| `firewall-cmd` | Supported high-level policy editor (`firewalld`) |
| `nft` | Native nftables CLI — sometimes the clearest truth on disk |
| `iptables-nft` | Classic syntax atop nft backend |

> **The point of the family tree:** Pick the **right viewer** for the question. `iptables -L` answers “filter chain policy + rules”; `nft list ruleset` answers “what did the kernel actually compile?”

---

## 🔬 The Anatomy of `iptables -L` — In One Diagram

```
$ iptables -L INPUT -n -v
Chain INPUT (policy ACCEPT 0 packets, 0 bytes)
 pkts bytes target   prot opt in   out   source      destination
    0     0 ACCEPT   all  --  *    *     0.0.0.0/0   0.0.0.0/0
    │     │    │      │    │  │    │        │            │
    │     │    │      │    │  │    │        │            └─ dst match (often 0.0.0.0/0 = "any")
    │     │    │      │    │  │    │        └─ src match
    │     │    │      │    │  │    └─ outbound interface (if matched)
    │     │    │      │    │  └─ inbound interface (lo, eth0, ...)
    │     │    │      │    └─ L3/L4 protocol (tcp, udp, all, ...)
    │     │    │      └─ options column (flags vary by match extensions)
    │     │    └─ verdict (ACCEPT/DROP/REJECT/LOG/chain-name...)
    │     └─ byte counter (since last zero/flush — informational)
    └─ packet counter
```

> **Reading rule:** State the **default policy** first (`policy ACCEPT` vs `DROP`), then read rules **top to bottom** until a match fires. If nothing matches, the policy wins.

---

## 📚 iptables Listing Reference Table

| Task | Command | Notes |
|---|---|---|
| Default filter view | `iptables -L` | Resolves DNS names in output unless `-n` |
| Numeric addresses/ports | `iptables -L -n` | Faster; essential on busy hosts |
| Verbose with counters | `iptables -L -v` or `-n -v` | Shows `pkts` / `bytes` |
| Line numbers (for inserts/deletes) | `iptables -L INPUT --line-numbers` | Pairs with `iptables -D INPUT N` (not exercised here) |
| Machine syntax | `iptables -S` | Matches `iptables-save` fragments |
| NAT perspective | `iptables -t nat -L -n -v` | PREROUTING/POSTROUTING tell DNAT/SNAT stories |
| See package | `rpm -qf $(command -v iptables)` | Confirms `iptables-nft` vs legacy tooling |

> **Rule one of inspection:** Never assume silence means “no firewall.” Always read **policy** plus **counters**.

---

## 🎯 Career Pathway Sidebar

| Level | Why this lab matters |
|---|---|
| **RHCSA candidate** | Objective wording still references classic firewall concepts. Showing chains proves you know **where** a rule would live. |
| **RHCE candidate** | Automation hides the chains — until it does not. Knowing how to verify the kernel ends state prevents “playbook succeeded, traffic still blocked.” |
| **SRE / Platform** | Outages love to ask: INPUT or FORWARD? Listing skills shorten MTTR. |
| **DevOps** | CI images and k8s nodes still ship with tables programmed by CNI plugins — vocabulary overlaps heavily. |
| **AI / MLOps** | When you expose an inference port, host-level drops look identical to application failures until you read the chain. |

---

## 🔧 The 6 Tasks

> Six phases that build **read-only fluency**, then a small **reporting capstone** with safe cleanup.

---

### Task 1 — Establish baseline: who owns firewall policy?

**Purpose:** Confirm `firewalld` is active (typical on RHEL 9), identify which `iptables` binary you are invoking, and capture a harmless default listing.

```bash
sudo -i
systemctl is-active firewalld || true
rpm -qf "$(command -v iptables)"
iptables --version
iptables -L | head -n 20
```

**Human-Readable Breakdown:** You are not changing policy yet. You are answering: “Is `firewalld` running?” and “Is this `iptables-nft`?” before interpreting listings.

**Reading it left to right:** `systemctl is-active` prints `active` or `inactive`. `rpm -qf` maps the binary to an RPM. `iptables --version` reveals the userspace backend string. `iptables -L | head` previews the default filter chains.

**The story:** The fastest way to embarrass yourself in a war room is to “fix iptables” on a host where `firewalld` immediately reprograms your edits. Look for the owner first.

**Expected output:**

```text
active
iptables-nft-1.8.8-9.el9.x86_64
iptables v1.8.8 (nf_tables)
Chain INPUT (policy ACCEPT)
target     prot opt source               destination
...
Chain FORWARD (policy ACCEPT)
...
Chain OUTPUT (policy ACCEPT)
...
```

**Switches**

| Token | Meaning |
|---|---|
| `systemctl is-active firewalld` | Prints `active`/`inactive`/`failed` — quick health |
| `command -v iptables` | Resolves the binary path you will execute |
| `rpm -qf PATH` | Shows which RPM installed that file |
| `iptables --version` | Reveals nftables-backed vs legacy string |
| `\| head -n 20` | Truncates long listings for first glance |

**Troubleshoot**

| Symptom | Fix |
|---|---|
| `iptables: command not found` | Install `iptables-nft` (package name may vary slightly by minor RHEL release) |
| `Permission denied (you must be root)` | Prefix with `sudo` or use `sudo -i` |
| Output scrolls for pages | That is normal; add `-n` and chain name in Task 3 |

---

### Task 2 — Read the filter table like a script: `iptables -L` vs `iptables -S`

**Purpose:** Compare human listings with the compact **save syntax** so both formats feel familiar.

```bash
sudo iptables -L
echo "---- save syntax ----"
sudo iptables -S
```

**Human-Readable Breakdown:** `-L` is columns and friendly-ish keywords. `-S` is the same rules expressed as if you were typing them back in — excellent for tickets and runbooks.

**Reading it left to right:** Without `-t`, both commands default to the **filter** table. Read each `INPUT` line in `-S` as “if match, jump to verdict.”

**The story:** Senior engineers screenshot `-S` because it pastes cleanly into chat without wrapping weirdly.

**Expected output:**

```text
Chain INPUT (policy ACCEPT)
...
-P INPUT ACCEPT
-A INPUT ... 
```

**Switches**

| Token | Meaning |
|---|---|
| `-L` | List rules |
| `-S` | Print rules in save/restore format |
| (default) | `filter` table when `-t` omitted |

**Troubleshoot**

| Symptom | Fix |
|---|---|
| Names resolve slowly | Add `-n` next task |
| `-S` is empty except policies | Host truly has no explicit rules in filter table |

---

### Task 3 — Numeric, verbose listings and INPUT line numbers

**Purpose:** Practice the production flags: no DNS, show counters, and show **line numbers** for chain surgery you may perform in later courses.

```bash
sudo iptables -L INPUT -n -v --line-numbers
sudo iptables -L FORWARD -n -v --line-numbers
sudo iptables -L OUTPUT -n -v --line-numbers
```

**Human-Readable Breakdown:** `-n` keeps output fast and unambiguous. `-v` exposes counters. `--line-numbers` prints the index column used by `-I` / `-D` in future labs.

**Reading it left to right:** Each row is evaluated in order until a rule matches; if none match, the **chain policy** (see header line) applies.

**The story:** Counters tell you whether a rule is **actually seeing traffic** or is dead code from an old change window.

**Expected output:**

```text
Chain INPUT (policy ACCEPT 0 packets, 0 bytes)
num   pkts bytes target   prot opt in   out   source      destination
1      123 45678 ACCEPT   tcp  --  *    *     0.0.0.0/0   0.0.0.0/0   tcp dpt:22
...
```

**Switches**

| Token | Meaning |
|---|---|
| `-n` | Numeric host/port display |
| `-v` | Verbose (counters) |
| `--line-numbers` | Index column for rule position |
| `INPUT` / `FORWARD` / `OUTPUT` | Limit listing to one chain |

**Troubleshoot**

| Symptom | Fix |
|---|---|
| Counters all zero | No traffic matched yet, or counters were cleared recently |
| You see unexpected `DROP` | Investigate owner daemon; capture full `nft list ruleset` |

---

### Task 4 — Peek at `nat` / `mangle` and correlate with `iptables-save`

**Purpose:** Prove you can leave the `filter` comfort zone and still read output safely.

```bash
sudo iptables -t nat -L -n -v | head -n 40
sudo iptables -t mangle -L -n -v | head -n 40
echo "---- top of iptables-save ----"
sudo iptables-save | head -n 40
```

**Human-Readable Breakdown:** NAT chains explain port forwards and masquerading. `mangle` is where QoS / TTL tweaks sometimes live. `iptables-save` dumps a concatenated snapshot you can compare to mental models.

**Reading it left to right:** `-t <table>` selects non-default tables. `iptables-save` streams all programmed tables the tool understands — still subject to what `firewalld` manages underneath.

**The story:** “SSH works but the forwarded port does not” is often a **nat** table story, not `INPUT`.

**Expected output:**

```text
Chain PREROUTING (policy ACCEPT)
...
Chain POSTROUTING (policy ACCEPT)
...
*mangle
:PREROUTING ACCEPT ...
...
```

**Switches**

| Token | Meaning |
|---|---|
| `-t nat` | Select NAT table |
| `-t mangle` | Select mangle table |
| `iptables-save` | Dump ruleset in restore-compatible format |

**Troubleshoot**

| Symptom | Fix |
|---|---|
| Empty `nat` table except policies | Normal on simple hosts without SNAT/DNAT |
| Confusing jumps to `f2b-*` or `KUBE-*` | Third-party chains — follow with `iptables -S` for full jumps |

---

### Task 5 — Edge case: zero counters, custom chains, and `nft` cross-check

**Purpose:** See whether **nft** exposes the same reality `iptables` summarized — a vital edge case on RHEL 9.

```bash
sudo iptables -L -n | grep '^Chain' 
sudo nft list ruleset 2>/dev/null | head -n 60 || echo "nft not installed or no permission"
```

**Human-Readable Breakdown:** Some environments install `nft` separately; if present, the first lines of `list ruleset` show tables/chains in native form.

**Reading it left to right:** `grep '^Chain'` extracts just chain headers from `iptables -L` for a compact index. `nft` output (if any) is the authoritative modern expression.

**The story:** When `iptables -L` and `nft` disagree, trust the mechanism your distribution wired — but **always** reconcile before changing rules by hand.

**Expected output:**

```text
Chain INPUT (policy ACCEPT)
Chain FORWARD (policy ACCEPT)
Chain OUTPUT (policy ACCEPT)
table inet firewalld { ... }
```

**Switches**

| Token | Meaning |
|---|---|
| `grep '^Chain'` | Only chain header lines |
| `nft list ruleset` | Native nftables view |
| `\|\| echo ...` | Friendly fallback if `nft` missing |

**Troubleshoot**

| Symptom | Fix |
|---|---|
| `nft: command not found` | Install `nftables` RPM on minimal images |
| Huge `nft` output | Pipe through `head` or `less` |

---

### Task 6 — Capstone documentation sweep and cleanup

**Purpose:** Produce a single **read-only report** under `/tmp` capturing the host story, then delete it. No firewall mutations in this lab.

```bash
REPORT=/tmp/iptables-lab-report.txt
{
  date
  echo "=== versions ==="
  iptables --version || true
  echo "=== filter INPUT ==="
  iptables -L INPUT -n -v --line-numbers || true
  echo "=== save snippet ==="
  iptables -S | head -n 50 || true
} | tee "$REPORT"

wc -l "$REPORT"
tail -n 5 "$REPORT"
```

**Human-Readable Breakdown:** You are building the habit of evidence bundles: version string, critical chain, save-syntax excerpt — enough to attach to a change ticket.

**Reading it left to right:** A grouped `{ ...; }` pipeline runs multiple ordered snapshots; `tee` writes and prints.

**The story:** In production, you would attach this file to the incident. In the lab, you practice the habit then remove the artifact.

**Expected output:**

```text
Tue May 26 10:15:00 UTC 2026
=== versions ===
iptables v1.8.8 (nf_tables)
=== filter INPUT ===
Chain INPUT (policy ACCEPT)
...
42 /tmp/iptables-lab-report.txt
```

**Switches**

| Token | Meaning |
|---|---|
| `{ ... } \| tee file` | Multi-command capture with duplicate stdout |
| `wc -l` | Confirms file length |
| `tail -n 5` | Quick sanity check of ending |

**Troubleshoot**

| Symptom | Fix |
|---|---|
| `tee: /tmp/iptables-lab-report.txt: Permission denied` | Run the block under `sudo -i` |
| Empty INPUT | Possible — still valid; note policy line |

**Cleanup**

```bash
rm -f /tmp/iptables-lab-report.txt
```

---

## 🔍 iptables Inspection Decision Guide

```
Need to understand host firewall?
  │
  ├── "Who programs rules day-to-day?"
  │       └── On RHEL 9: usually firewalld → still peek with iptables/nft for truth
  │
  ├── "Is local traffic blocked?"
  │       └── Start: iptables -L INPUT -n -v --line-numbers
  │
  ├── "Is forwarded/NAT traffic wrong?"
  │       └── iptables -t nat -L -n -v
  │
  ├── "Do counters prove the rule fires?"
  │       └── iptables -L CHAIN -n -v (watch pkts/bytes)
  │
  ├── "What would I paste into a ticket?"
  │       └── iptables -S (or full iptables-save with care)
  │
  └── "What does nft say natively?"
          └── nft list ruleset (first 200 lines, then search)
```

---

## ✅ Lab Checklist (6 Tasks)

- [ ] 01 Confirm `firewalld` activity, RPM owner of `iptables`, and preview default `-L` output
- [ ] 02 Compare `iptables -L` with `iptables -S` for the filter table
- [ ] 03 List INPUT/FORWARD/OUTPUT with `-n -v` and `--line-numbers`
- [ ] 04 Inspect `nat` and `mangle`, then sample `iptables-save`
- [ ] 05 Extract chain headers; optional `nft list ruleset` cross-check
- [ ] 06 Build `/tmp` report with `tee`, verify, delete file in Cleanup

---

## ⚠️ Common Pitfalls

| Mistake | Symptom | Fix |
|---|---|---|
| Assuming `-L` shows all tables | Missing NAT story | Add `-t nat` explicitly |
| Reading bottom-to-top | Wrong mental model | Rules match top-down; policy is last resort |
| Editing raw tables while `firewalld` runs | Changes vanish or fight daemon | Use `firewall-cmd` for supported changes |
| Ignoring counters | “Rule exists” but no effect | Use `-v`; verify traffic hits the row |
| DNS lookups on busy nets | Slow `iptables -L` | Always add `-n` in production |
| Confusing `iptables` legacy vs nft | Strange errors | Read `iptables --version` string |

---

## 🎯 Career & Interview Strategy

**RHCSA candidate**
- Be ready to name the three filter chains and state default policy vs explicit rules.

**RHCE candidate**
- Explain how automation should **verify** kernel state (`iptables-save` / `nft`) after playbooks run.

**SRE / Platform interview**
- Walk through diagnosing “port closed”: socket listening? `ss`? then chain counters in `INPUT`.

**DevOps**
- Relate host rules to container published ports — double NAT is a frequent foot-gun.

**AI / MLOps**
- Treat inference endpoints like any other service: prove LISTEN, then prove `INPUT` accepts.

---

## 🔗 Related Labs

| Lab | Connection |
|---|---|
| [firewalld-zones](https://github.com/kelvintechnical/firewalld-zones) | High-level zones vs low-level chain view |
| [active-firewall-zones](https://github.com/kelvintechnical/active-firewall-zones) | Operational review of bindings and services |
| [firewalld-add-services](https://github.com/kelvintechnical/firewalld-add-services) | Opening named services persistently |
| [firewalld-custom-ports](https://github.com/kelvintechnical/firewalld-custom-ports) | Non-standard ports |

---

## 👤 Author

**Kelvin R. Tobias**
[kelvinintech.com](https://kelvinintech.com) · [GitHub](https://github.com/kelvintechnical) · [LinkedIn](https://www.linkedin.com/in/kelvin-r-tobias-211949219)
