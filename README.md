# BETA: hashcat_wrapper.py (Hashcat Wrapper TUI)

A **Textual**-based terminal UI (TUI) front-end for building and running **Hashcat** commands interactively. It focuses on repeatable “recipe” selection (hash file + mode + rules + wordlists + flags), adds safety checks via history, and supports piping input from **PRINCE Processor**.

> This is a wrapper/UI for driving your own Hashcat installation. It does not include Hashcat or wordlists.

> On wsl you have to cd to your windows version of hashcat so that OpenCL works
---

## Features

- **Cross-platform detection:** Linux / WSL / Windows-aware behavior.
- **Config editing in-app**:
  - Hashcat binary path per platform
  - PRINCE processor binary path per platform
  - Directories for:
    - hash files
    - rules
    - wordlists
    - PRINCE wordlists
  - hash mode list editor
  - default flags, default output file, “warn_days”
- **Hash file browser**
  - select a directory filter
  - filter file list by substring
  - manual path entry mode
- **Mode picker** with filtering (from your configured hash modes)
- **Multi-select** for:
  - rules (`.rule`, `.rules`, recursive scan)
  - wordlists (`.txt`, `.lst`, `.dict`)
- **PRINCE mode support**
  - toggle PRINCE on/off
  - pass PRINCE args
  - choose PRINCE input wordlist (or fall back to first selected wordlist)
- **Command history** persisted to JSON
  - “recent run” warnings based on full command fingerprint (file, mode, rules, wordlists, flags, PRINCE settings)
  - view last ~50 runs in a table
- **Streaming output in the UI** using a PTY (supports interactive hashcat keys)
- **Copy-to-clipboard** (optional dependency)

---

## Requirements

- Python **3.10+**
- [`textual`](https://pypi.org/project/textual/)
- Optional: [`pyperclip`](https://pypi.org/project/pyperclip/) for clipboard support

Install:

```bash
pip install textual pyperclip
```

If you don’t install `pyperclip`, the app will still run, but “Copy” will print the command to the output log instead of copying it.

---

## Quick Start

1. Place `hashcat_wrapper.py` in a directory where you want its config/history files stored.
2. Run it:

```bash
python3 hashcat_wrapper.py
```

3. Press **e** to open the **Config** editor and set:
   - your hashcat binary path (per platform)
   - directories containing hash files, rules, and wordlists

4. Select:
   - a hash file (or manual path)
   - a hash mode
   - any rules / wordlists

5. Press **r** (Run) to execute.

---

## Key Bindings (Main Screen)

- `r` — Run
- `c` — Copy generated command (clipboard if available)
- `h` — View history
- `e` — Edit config
- `q` — Quit

### Hashcat interactive keys (sent to the running process via PTY)

These are passed to hashcat while it’s running:

- `s` — Status
- `b` — Breakpoint
- `p` — Pause
- `o` — Resume (sends `r` to hashcat; bound to `o` to avoid clashing with “run”)
- `x` — Quit/stop hashcat (sends `q` to hashcat)

> Note: These only work while a process is running and attached via PTY.

---

## Configuration & Data Files

The script stores config and history in the **same directory as the script**:

- `hashcat_config.json` — persistent configuration
- `hashcat_history.json` — command history / fingerprints

### Default config (high level)

The app seeds missing keys from an internal `DEFAULT_CONFIG`, including:

- `hashcat.windows`, `hashcat.wsl`, `hashcat.linux`
- `princeprocessor.windows`, `princeprocessor.wsl`, `princeprocessor.linux`
- `rules_directories`
- `wordlist_directories`
- `prince_wordlist_directories`
- `hash_files_directories`
- `hash_modes` (common starter set)
- `warn_days` (default 7)
- `default_output_file` (default `master.txt`)
- `default_flags` (e.g. `--self-test-disable`, `--bitmap-max 26`)

The config editor lets you update all of these.

---

## WSL Notes (Running Windows hashcat.exe from WSL)

This wrapper explicitly supports a common setup: **running `hashcat.exe` from WSL**.

When the configured hashcat binary ends in `.exe`, the command builder will convert file paths:

- `/mnt/c/...` → `C:\...` directly
- other Linux paths (e.g. `/home/...`) attempt `wslpath -w` conversion

It also runs commands through **bash** when needed so WSL interop correctly launches `.exe` binaries and handles pipes.

---

## How Commands Are Built

The command builder produces a full shell command string, roughly:

### Normal mode (no PRINCE)

```text
hashcat -m <mode> -a 0 -o <output_file> \
  -r <rule1> -r <rule2> \
  <hash_file> <wordlist1> <wordlist2> \
  <default_flags> <extra_flags>
```

### PRINCE mode (piped to hashcat stdin)

```text
pp64 <prince_args> < <prince_input> | \
hashcat -m <mode> -a 0 -o <output_file> <hash_file> --stdin \
  -r <rule1> -r <rule2> \
  <default_flags> <extra_flags>
```

The exact output depends on your selections and config.

---

## History / “Recent Run” Warning

Before running, the app can warn if an **equivalent run** occurred recently (within `warn_days`), comparing:

- hash file path
- mode
- selected wordlists
- selected rules
- extra flags
- PRINCE enabled/disabled
- PRINCE args
- PRINCE input

This is meant to prevent accidentally re-running the same job repeatedly.

---

## Troubleshooting

### “pyperclip not installed”
Install it:

```bash
pip install pyperclip
```

Or ignore it—copy will print the command.

### Hashcat won’t start on WSL when using `.exe`
Ensure your configured `hashcat.wsl` points to `hashcat.exe` and that Windows interop is enabled in WSL. Also prefer putting data under `/mnt/c/...` so path conversion is straightforward.

### No files show up in the lists
Open **Config** (`e`) and add:
- `hash_files_directories`
- `rules_directories`
- `wordlist_directories`

The UI only lists files inside configured directories.

---

## Security / Legal

This tool is intended for authorized security testing, password recovery, and training in controlled environments. Make sure you have permission to audit any hashes you attempt to crack.

---

## License

Add your project’s license here (e.g., MIT) or link to `LICENSE`.
