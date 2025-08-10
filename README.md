# Merkle-Run — Lightweight, Tamper-Evident, Deterministic Python Runner
 Merkle-Run is a minimal but powerful tool that runs any Python script under full observation, recording every side effect (file I/O, subprocess calls, network attempts, randomness) in a tamper-evident Merkle chain log.

It can:
- Block or allow network access
- Track exactly how many network connections were attempted
- Capture deterministic seeds for reproducible runs
- Replay and compare runs to detect hidden behavior or non-determinism

All of this works **without modifying the target script** and **without any special OS-level permissions** — just pure Python monkeypatching.

---

## 🔍 How it compares to existing tools

There are already tools for tracking what a program does so it can be reproduced later:

- ReproZip (https://www.reprozip.org/) — records everything a program does at the operating system level (system calls) and packages it for replay elsewhere.  
- noWorkflow (https://github.com/gems-uff/noworkflow) — tracks the full provenance of a Python script with deep analysis, but is heavy and complex.  
- ReciPy (https://github.com/recipy/recipy) — logs input/output files used by a Python script, but requires modifying the script to use it.

*What doesn’t really exist yet* is a *tiny* tool that:

1. **Observes** all Python script actions simply by replacing a few basic built-in functions (monkeypatching — no script or OS modification required).  
2. **Records each event** in a secure log with a Merkle hash chain (like a mini blockchain).  
3. **Blocks or allows network access** and counts every connection attempt.  
4. **Replays the script** in the same conditions and shows differences.  
5. Works with **no extra system dependencies** and no privileged permissions.

Existing tools are powerful but heavy and complex — **Merkle-Run** aims to be **lightweight, educational, and innovative**.

Why it’s interesting
Cybersecurity — Detect hidden or suspicious behavior in scripts.

Reproducibility — Ensure experiments and processes can be repeated exactly.

Forensics — Tamper-evident logs for later investigation.

Education — Learn monkeypatching, Merkle trees, determinism, and I/O tracing in one project.


💡 **OUR Current Problem**
When you want to monitor what a program does, existing tools are often:

Very heavy — they listen to everything happening at the operating system level (e.g., ReproZip).

Too complex — they perform deep analyses that slow things down (e.g., noWorkflow).

Intrusive — they require you to modify your code to work (e.g., ReciPy).

And often, these tools are built for researchers or large teams, not for someone who just wants a small, easy-to-run utility.

🚀 **How Our Project Changes This**
Merkle-Run is revolutionary in its simplicity:

It does not modify your script.

It does not modify your system (no admin rights needed).

It sees everything the script does (opened files, internet activity, subprocess calls, randomness).

It can block certain actions (e.g., block the internet).

It keeps a tamper-evident proof of everything that happened (via a Merkle hash chain).

It can replay the script exactly to see if it behaves the same way — perfect for detecting hidden or unreliable behavior.

🎯 **Why It’s Rare**
Other tools either record actions or block them, but not both in a lightweight format.

To my knowledge, no one has built a mini Python runner that does this purely with monkeypatching (temporary replacement of functions) and without heavy dependencies.

The Merkle approach for logs is common in blockchain, but rarely applied to program execution monitoring.

---

## 🚀 Quick Start

```bash
# run a script under monitoring
python merklerun.py run example_target.py --seed 42 --allow-net 0 --out manifest.json

# replay the script and verify determinism
python merklerun.py verify example_target.py manifest.json --seed 42 --allow-net 0

# compare two different runs
python merklerun.py diff manifest_a.json manifest_b.json






📂 Output Example (manifest.json)

{
  "started_at_utc": "2025-08-10T12:34:56Z",
  "seed": 42,
  "allow_net": false,
  "events": [
    {
      "t": 0.000001,
      "kind": "begin",
      "target": "/path/to/example_target.py",
      "args": [],
      "chain": "5df6e0e2..."
    },
    {
      "t": 0.003451,
      "kind": "file_open",
      "path": "/path/to/out.bin",
      "mode": "wb",
      "chain": "a41b3d90..."
    }
  ],
  "root_hash": "28bc63f4..."
}
The root hash acts as a fingerprint of the entire run — change even one event, and the hash changes.



