#!/usr/bin/env python3
"""
hashcat_tui.py — Textual TUI front-end for Hashcat.

Implements all features of hashcat_helper.py in a terminal UI:
  • Full config editing (paths, directories, hash modes, flags, warn_days)
  • Hash file browser with per-directory filter and manual entry
  • Multi-select rules and wordlists
  • PRINCE processor support (toggle, args, input wordlist)
  • Command history with recency warnings
  • Streaming subprocess output
  • Copy-to-clipboard

Requires: Python 3.10+, textual, pyperclip (optional for clipboard)
  pip install textual pyperclip
"""

from __future__ import annotations

import fcntl, termios, struct
import json
import os
import platform
import pty
import re
import select
import shlex
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen, Screen
from textual.widgets import (
    Button,
    Checkbox,
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    ListItem,
    ListView,
    Log,
    Static,
)

try:
    import pyperclip as _pyperclip
    _HAS_PYPERCLIP = True
except ImportError:
    _HAS_PYPERCLIP = False

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
SCRIPT_DIR = Path(__file__).resolve().parent
CONFIG_FILE = SCRIPT_DIR / "hashcat_config.json"
HISTORY_FILE = SCRIPT_DIR / "hashcat_history.json"

# ---------------------------------------------------------------------------
# Platform detection (robust — checks env vars then /proc/version)
# ---------------------------------------------------------------------------

def _detect_platform() -> str:
    """Return 'windows', 'wsl', or 'linux'."""
    if platform.system() == "Windows":
        return "windows"
    if os.environ.get("WSL_DISTRO_NAME") or os.environ.get("WSLENV"):
        return "wsl"
    try:
        pv = Path("/proc/version").read_text(encoding="utf-8", errors="ignore").lower()
        if "microsoft" in pv or "wsl" in pv:
            return "wsl"
    except OSError:
        pass
    return "linux"


_PLATFORM = _detect_platform()

# ---------------------------------------------------------------------------
# WSL ↔ Windows path conversion
# ---------------------------------------------------------------------------

def _to_win_path(path: str) -> str:
    """
    Convert a Linux/WSL path to the equivalent Windows path for use when
    invoking a Windows .exe (e.g. hashcat.exe) from WSL.

    Conversion rules
    ----------------
    /mnt/<drive>/...  →  <DRIVE>:\\...          (DrvFs mount — most common)
    /home/..., /root/...                        call ``wsl.exe -e wslpath -w``
    Paths that already look like Windows paths  returned unchanged
    """
    p = path.strip()

    # Already a Windows path (C:\... or \\...)
    if re.match(r"^[A-Za-z]:\\", p) or p.startswith("\\\\"):
        return p

    # /mnt/<drive>/... — convert directly without spawning a subprocess
    mnt_match = re.match(r"^/mnt/([a-zA-Z])(/.*)?$", p)
    if mnt_match:
        drive = mnt_match.group(1).upper()
        rest = (mnt_match.group(2) or "").replace("/", "\\")
        return f"{drive}:{rest}"

    # Paths inside the WSL filesystem (e.g. /home/...) — use wslpath
    try:
        result = subprocess.run(
            ["wsl.exe", "-e", "wslpath", "-w", p],
            capture_output=True,
            text=True,
            timeout=5,
        )
        converted = result.stdout.strip()
        if converted:
            return converted
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass

    # Last resort: return as-is (hashcat.exe might handle it or give a clear error)
    return p


def _win_paths_needed(cfg: dict) -> bool:
    """Return True when the hashcat binary is a Windows .exe (needs Win paths)."""
    hashcat_bin = cfg.get("hashcat", {}).get(_PLATFORM, "")
    return hashcat_bin.lower().endswith(".exe")


# ---------------------------------------------------------------------------
# JSON helpers
# ---------------------------------------------------------------------------

def _load_json(path: Path, default):
    if not path.exists():
        return default
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (json.JSONDecodeError, OSError) as exc:
        # Warn to stderr so the TUI log isn't polluted, but don't crash.
        print(f"[!] Warning: could not read {path}: {exc}", file=sys.stderr)
        return default


def _save_json(path: Path, data) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=4)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DEFAULT_CONFIG: dict = {
    "hashcat": {
        "windows": "hashcat.exe",
        "wsl":     "hashcat.exe",
        "linux":   "hashcat",
    },
    "princeprocessor": {
        "windows": "C:\\PenTesting\\data\\princeprocessor\\pp64.exe",
        "wsl":     "/mnt/c/PenTesting/data/princeprocessor/pp64.exe",
        "linux":   "/home/user/princeprocessor/pp64.bin",
    },
    "rules_directories": ["rules", "/mnt/c/PenTesting/data/hashcat-6.2.6/rules"],
    "wordlist_directories": [],
    "prince_wordlist_directories": [],
    "hash_files_directories": [],
    "hash_modes": {
        "0":     "MD5",
        "100":   "SHA1",
        "500":   "md5crypt ($apr1$ / $1$)",
        "1000":  "NTLM",
        "1800":  "sha512crypt ($6$)",
        "3000":  "LM",
        "5500":  "NetNTLMv1 / NetNTLMv1+ESS",
        "5600":  "NetNTLMv2",
        "13100": "Kerberos 5 TGS-REP etype 23",
        "18200": "Kerberos 5 AS-REP etype 23",
        "22000": "WPA-PBKDF2-PMKID+EAPOL",
    },
    "warn_days": 7,
    "default_output_file": "master.txt",
    "default_flags": ["--self-test-disable", "--bitmap-max 26"],
}


def load_config() -> dict:
    cfg = _load_json(CONFIG_FILE, {})
    # Migrate legacy single-string key to the list form
    if "hash_files_directory" in cfg:
        old = cfg.pop("hash_files_directory", "")
        if old and "hash_files_directories" not in cfg:
            cfg["hash_files_directories"] = [old]
    # Fill in any missing top-level keys from defaults
    for k, v in DEFAULT_CONFIG.items():
        cfg.setdefault(k, v)
    return cfg


def save_config(cfg: dict) -> None:
    _save_json(CONFIG_FILE, cfg)

# ---------------------------------------------------------------------------
# History
# ---------------------------------------------------------------------------

def load_history() -> list:
    return _load_json(HISTORY_FILE, [])


def save_history(history: list) -> None:
    _save_json(HISTORY_FILE, history)


def record_command(
    cmd: str,
    hash_file: str,
    mode: str,
    wordlists: list[str],
    rules: list[str],
    extra_flags: str,
    use_prince: bool,
    prince_args: str,
    prince_input: str,
) -> None:
    history = load_history()

    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "hash_file": hash_file,
        "mode": mode,
        "command": cmd,

        # 🔥 fingerprint fields
        "wordlists": sorted(wordlists),
        "rules": sorted(rules),
        "extra_flags": extra_flags.strip(),
        "use_prince": use_prince,
        "prince_args": prince_args.strip(),
        "prince_input": prince_input.strip(),
    }

    history.append(entry)
    save_history(history)


def check_recent(
    hash_file: str,
    mode: str,
    wordlists: list[str],
    rules: list[str],
    extra_flags: str,
    use_prince: bool,
    prince_args: str,
    prince_input: str,
    warn_days: int,
) -> list[dict]:

    now = datetime.now(timezone.utc)

    target = {
        "hash_file": hash_file,
        "mode": mode,
        "wordlists": sorted(wordlists),
        "rules": sorted(rules),
        "extra_flags": extra_flags.strip(),
        "use_prince": use_prince,
        "prince_args": prince_args.strip(),
        "prince_input": prince_input.strip(),
    }

    matches = []

    for entry in load_history():
        try:
            ts = datetime.fromisoformat(entry["timestamp"])
            age = (now - ts).days
            if age > warn_days:
                continue
        except Exception:
            continue

        # 🔥 Compare full configuration
        if (
            entry.get("hash_file") == target["hash_file"]
            and entry.get("mode") == target["mode"]
            and sorted(entry.get("wordlists", [])) == target["wordlists"]
            and sorted(entry.get("rules", [])) == target["rules"]
            and entry.get("extra_flags", "").strip() == target["extra_flags"]
            and entry.get("use_prince") == target["use_prince"]
            and entry.get("prince_args", "").strip() == target["prince_args"]
            and entry.get("prince_input", "").strip() == target["prince_input"]
        ):
            matches.append({**entry, "age_days": age})

    return matches

# ---------------------------------------------------------------------------
# File enumeration
# ---------------------------------------------------------------------------

def _list_files(
    directories: list[str],
    extensions: list[str] | None = None,
    recursive: bool = False,
) -> list[str]:
    files: list[str] = []
    for d in directories:
        p = Path(d)
        if not p.is_absolute():
            p = SCRIPT_DIR / p
        if not p.is_dir():
            continue
        iterator = sorted(p.rglob("*")) if recursive else sorted(p.iterdir())
        for f in iterator:
            if f.is_file():
                if extensions is None or f.suffix.lower() in extensions:
                    files.append(str(f))
    return files


def list_rules(cfg: dict) -> list[str]:
    return _list_files(cfg.get("rules_directories", []), [".rule", ".rules"], recursive=True)


def list_wordlists(cfg: dict) -> list[str]:
    return _list_files(cfg.get("wordlist_directories", []), [".txt", ".lst", ".dict"])


def list_hash_files(cfg: dict) -> list[str]:
    """All files inside hash_files_directories (no extension filter)."""
    return _list_files(cfg.get("hash_files_directories", []))

# ---------------------------------------------------------------------------
# Command builder (full implementation from hashcat_helper.py)
# ---------------------------------------------------------------------------

def build_hashcat_command(
    cfg: dict,
    hash_file: str,
    mode: str,
    wordlists: list[str],
    rules: list[str],
    output_file: str,
    extra_flags: str = "",
    use_prince: bool = False,
    prince_args: str = "",
    prince_input: str = "",
) -> str:
    """Return the full shell command string.

    When the configured hashcat binary is a Windows .exe (e.g. running from
    WSL), all file paths are converted to Windows format (``C:\\...``) because
    hashcat.exe cannot interpret Linux/WSL paths such as ``/mnt/c/...``.
    The binary path itself and the prince binary path are also converted so
    the shell can resolve them via WSL interop.
    """
    hashcat_bin = cfg["hashcat"].get(_PLATFORM, cfg["hashcat"].get("linux", "hashcat"))
    prince_bin = cfg["princeprocessor"].get(_PLATFORM, cfg["princeprocessor"].get("linux", "pp64.bin"))
    
    # When invoking a Windows .exe, convert every Linux/WSL path to its
    # Windows equivalent so hashcat.exe (and pp64.exe) can read the files.
    win = _win_paths_needed(cfg)
    def p(path: str) -> str:  # path converter
        return _to_win_path(path) if win else path

    q = shlex.quote
    rule_flags = " ".join(f"-r {q(p(r))}" for r in rules)
    wordlist_str = " ".join(q(p(w)) for w in wordlists)
    default_flags = " ".join(cfg.get("default_flags", []))
    extra = extra_flags.strip()

    if os.path.isabs(hashcat_bin):
        hc = q(hashcat_bin)
    else:
        hc = hashcat_bin
    
    hf = q(p(hash_file))
    of = q(p(output_file))

    if use_prince:
        p_input = prince_input or (wordlists[0] if wordlists else "")
        pp = q(p(prince_bin))
        prince_part = (
            f"{pp} {prince_args} < {q(p(p_input))}" if p_input else pp
        )
        hashcat_part = (
            f"{hc} -m {mode} -a 0 -o {of} {hf} "
            f"--stdin {rule_flags} {default_flags} {extra}"
        ).strip()
        cmd = f"{prince_part} | {hashcat_part}"
    else:
        cmd = (
            f"{hc} -m {mode} -a 0 -o {of} "
            f"{rule_flags} {hf} {wordlist_str} "
            f"{default_flags} {extra}"
        ).strip()

    return re.sub(r" {2,}", " ", cmd)

# ---------------------------------------------------------------------------
# Execution helper — determines whether shell=True is required
# ---------------------------------------------------------------------------

def _needs_shell(cmd: str, use_prince: bool) -> bool:
    """
    Return True if the command must be run through the shell.

    shell=True is required when:
      • PRINCE mode uses a pipe
      • The platform is WSL (Windows .exe via WSL interop)
      • The binary is a Windows .exe (detects PE binary regardless of WSL env
        detection — avoids OSError: [Errno 8] Exec format error)

    Note: _stream_command pairs shell=True with executable="/bin/bash" so that
    bash (not dash/sh) handles the command.  bash honours WSL binfmt_misc
    interop for .exe files; dash does not, causing exit 126.
    """
    try:
        binary = shlex.split(cmd)[0]
    except (ValueError, IndexError):
        binary = ""
    return use_prince or _PLATFORM == "wsl" or binary.lower().endswith(".exe")

# ---------------------------------------------------------------------------
# TUI — Warning dialog
# ---------------------------------------------------------------------------

class WarnDialog(ModalScreen):
    """Modal warning when the same hash file + mode was run recently."""

    DEFAULT_CSS = """
    WarnDialog {
        align: center middle;
    }
    #warn_box {
        width: 70;
        padding: 2 4;
        border: solid $warning;
        background: $surface;
    }
    #warn_text { color: $warning; margin-bottom: 1; }
    #warn_buttons { margin-top: 1; }
    """

    def __init__(self, matches: list[dict], warn_days: int) -> None:
        super().__init__()
        self._matches = matches
        self._warn_days = warn_days

    def compose(self) -> ComposeResult:
        lines = [
            f"\u26a0  WARNING: This hash file + mode was run {len(self._matches)} "
            f"time(s) in the last {self._warn_days} day(s):\n"
        ]
        for m in self._matches[-3:]:
            cmd_prev = m.get("command", "")
            if len(cmd_prev) > 65:
                cmd_prev = cmd_prev[:65] + "\u2026"
            lines.append(f"  {m.get('timestamp', '')[:10]}  {cmd_prev}")

        with Vertical(id="warn_box"):
            yield Static("\n".join(lines), id="warn_text", markup=False)
            with Horizontal(id="warn_buttons"):
                yield Button("Continue anyway", id="warn_continue", variant="warning")
                yield Button("Cancel", id="warn_cancel", variant="primary")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "warn_continue")

# ---------------------------------------------------------------------------
# TUI — History screen
# ---------------------------------------------------------------------------

class HistoryScreen(Screen):
    """Full-screen history viewer (last 50 entries, newest first)."""

    BINDINGS = [Binding("escape", "back", "Back")]

    def __init__(self, cfg: dict) -> None:
        super().__init__()
        self._cfg = cfg

    def compose(self) -> ComposeResult:
        yield Header()
        history = load_history()
        warn_days = self._cfg.get("warn_days", 7)
        now = datetime.now(timezone.utc)

        table: DataTable = DataTable(id="hist_table")
        table.add_columns("#", "Date (UTC)", "Age", "Mode", "File", "Command")

        for i, entry in enumerate(reversed(history[-50:]), 1):
            ts_raw = entry.get("timestamp", "")
            try:
                ts = datetime.fromisoformat(ts_raw)
                age = (now - ts).days
                ts_fmt = ts.strftime("%Y-%m-%d %H:%M")
                age_str = f"{age}d"
                flag = " \u26a0" if age <= warn_days else ""
            except ValueError:
                ts_fmt = ts_raw[:16]
                age_str = "?"
                flag = ""

            cmd_short = entry.get("command", "")
            if len(cmd_short) > 55:
                cmd_short = cmd_short[:55] + "\u2026"

            table.add_row(
                str(i),
                ts_fmt + flag,
                age_str,
                entry.get("mode", "?"),
                Path(entry.get("hash_file", "?")).name,
                cmd_short,
            )

        yield table
        yield Button("\u2190 Back", id="hist_back")
        yield Footer()

    def action_back(self) -> None:
        self.dismiss()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "hist_back":
            self.dismiss()

# ---------------------------------------------------------------------------
# TUI — Config editor screen
# ---------------------------------------------------------------------------

class ConfigScreen(Screen):
    """
    Scrollable configuration editor.

    Dismisses with the updated config dict on save, or None on discard.
    """

    BINDINGS = [Binding("escape", "discard", "Discard & back")]

    DEFAULT_CSS = """
    ConfigScreen { layout: vertical; }
    #cfg_scroll { height: 1fr; }
    .cfg_hdr { color: $accent; text-style: bold; margin-top: 1; }
    .cfg_row { layout: horizontal; height: auto; }
    Input { margin-bottom: 0; }
    Button { margin: 0 1; }
    """

    def __init__(self, cfg: dict) -> None:
        super().__init__()
        # Work on a deep copy so discard truly discards
        self._cfg: dict = json.loads(json.dumps(cfg))

    def compose(self) -> ComposeResult:
        plat = _PLATFORM
        cfg = self._cfg

        yield Header()
        with VerticalScroll(id="cfg_scroll"):
            yield Static(f"Hashcat binary  ({plat})", classes="cfg_hdr")
            yield Input(
                value=cfg["hashcat"].get(plat, cfg["hashcat"].get("linux", "")),
                placeholder="Full path to hashcat binary",
                id="cfg_hashcat",
            )

            yield Static(f"Princeprocessor binary  ({plat})", classes="cfg_hdr")
            yield Input(
                value=cfg["princeprocessor"].get(plat, cfg["princeprocessor"].get("linux", "")),
                placeholder="Full path to pp64 binary",
                id="cfg_prince_bin",
            )

            yield Static("Default output file", classes="cfg_hdr")
            yield Input(
                value=cfg.get("default_output_file", "master.txt"),
                id="cfg_out_file",
            )

            yield Static("Default flags (space-separated)", classes="cfg_hdr")
            yield Input(
                value=" ".join(cfg.get("default_flags", [])),
                id="cfg_def_flags",
            )

            yield Static("Warn days (warn if same target run within N days)", classes="cfg_hdr")
            yield Input(value=str(cfg.get("warn_days", 7)), id="cfg_warn_days")

            # ---- directory lists ----
            for key, label, disp_id, add_id, rm_id, btn_add, btn_rm in [
                ("hash_files_directories",      "Hash Files Directories",       "disp_hash",   "add_hash",   "rm_hash",   "badd_hash",  "brm_hash"),
                ("rules_directories",           "Rules Directories",            "disp_rules",  "add_rules",  "rm_rules",  "badd_rules", "brm_rules"),
                ("wordlist_directories",        "Wordlist Directories",         "disp_wl",     "add_wl",     "rm_wl",     "badd_wl",    "brm_wl"),
                ("prince_wordlist_directories", "PRINCE Wordlist Directories",  "disp_pwl",    "add_pwl",    "rm_pwl",    "badd_pwl",   "brm_pwl"),
            ]:
                yield Static(label, classes="cfg_hdr")
                yield Static(
                    self._fmt_dirs(cfg.get(key, [])),
                    id=disp_id,
                )
                with Horizontal(classes="cfg_row"):
                    yield Input(placeholder="Path to add", id=add_id)
                    yield Button("Add", id=btn_add)
                    yield Input(placeholder="Number to remove", id=rm_id)
                    yield Button("Remove", id=btn_rm)

            # ---- hash modes ----
            yield Static("Hash Modes", classes="cfg_hdr")
            yield Static(self._fmt_modes(cfg.get("hash_modes", {})), id="disp_modes")
            with Horizontal(classes="cfg_row"):
                yield Input(placeholder="number:description", id="add_mode_inp")
                yield Button("Add Mode", id="badd_mode")
            with Horizontal(classes="cfg_row"):
                yield Input(placeholder="mode number to remove", id="rm_mode_inp")
                yield Button("Remove Mode", id="brm_mode")

            with Horizontal(classes="cfg_row"):
                yield Button("\U0001f4be Save & Close", id="cfg_save", variant="success")
                yield Button("\u2717 Discard", id="cfg_discard", variant="error")

        yield Footer()

    # ---- formatting helpers ----

    @staticmethod
    def _fmt_dirs(dirs: list[str]) -> str:
        return "\n".join(f"  [{i}] {d}" for i, d in enumerate(dirs, 1)) or "  (none)"

    @staticmethod
    def _fmt_modes(modes: dict) -> str:
        if not modes:
            return "  (none)"
        return "\n".join(
            f"  {k:>6}  {v}"
            for k, v in sorted(modes.items(), key=lambda x: int(x[0]))
        )

    def _refresh(self, disp_id: str, key: str) -> None:
        cfg = self._cfg
        if "directories" in key:
            self.query_one(f"#{disp_id}", Static).update(
                self._fmt_dirs(cfg.get(key, []))
            )
        elif key == "hash_modes":
            self.query_one(f"#{disp_id}", Static).update(
                self._fmt_modes(cfg.get(key, {}))
            )

    # ---- directory add/remove ----

    def _add_dir(self, inp_id: str, key: str, disp_id: str) -> None:
        inp = self.query_one(f"#{inp_id}", Input)
        val = inp.value.strip()
        if val:
            lst: list[str] = self._cfg.setdefault(key, [])
            if val not in lst:
                lst.append(val)
            inp.value = ""
            self._refresh(disp_id, key)

    def _rm_dir(self, inp_id: str, key: str, disp_id: str) -> None:
        inp = self.query_one(f"#{inp_id}", Input)
        val = inp.value.strip()
        if val.isdigit():
            lst: list[str] = self._cfg.get(key, [])
            idx = int(val) - 1
            if 0 <= idx < len(lst):
                lst.pop(idx)
            inp.value = ""
            self._refresh(disp_id, key)

    # ---- button dispatcher ----

    def on_button_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id

        _dir_map: dict[str, tuple[str, str, str]] = {
            "badd_hash":  ("add_hash",  "hash_files_directories",      "disp_hash"),
            "brm_hash":   ("rm_hash",   "hash_files_directories",      "disp_hash"),
            "badd_rules": ("add_rules", "rules_directories",           "disp_rules"),
            "brm_rules":  ("rm_rules",  "rules_directories",           "disp_rules"),
            "badd_wl":    ("add_wl",    "wordlist_directories",        "disp_wl"),
            "brm_wl":     ("rm_wl",     "wordlist_directories",        "disp_wl"),
            "badd_pwl":   ("add_pwl",   "prince_wordlist_directories", "disp_pwl"),
            "brm_pwl":    ("rm_pwl",    "prince_wordlist_directories", "disp_pwl"),
        }

        if bid in _dir_map:
            inp_id, key, disp_id = _dir_map[bid]
            if bid.startswith("badd_"):
                self._add_dir(inp_id, key, disp_id)
            else:
                self._rm_dir(inp_id, key, disp_id)

        elif bid == "badd_mode":
            raw = self.query_one("#add_mode_inp", Input).value.strip()
            if ":" in raw:
                num, desc = raw.split(":", 1)
                self._cfg.setdefault("hash_modes", {})[num.strip()] = desc.strip()
                self.query_one("#add_mode_inp", Input).value = ""
                self._refresh("disp_modes", "hash_modes")

        elif bid == "brm_mode":
            num = self.query_one("#rm_mode_inp", Input).value.strip()
            modes = self._cfg.get("hash_modes", {})
            if num in modes:
                del modes[num]
                self.query_one("#rm_mode_inp", Input).value = ""
                self._refresh("disp_modes", "hash_modes")

        elif bid == "cfg_save":
            self._collect_and_save()

        elif bid == "cfg_discard":
            self.dismiss(None)

    def _collect_and_save(self) -> None:
        """Read all Input widgets, update _cfg, persist, and dismiss."""
        plat = _PLATFORM
        cfg = self._cfg

        hc = self.query_one("#cfg_hashcat", Input).value.strip()
        if hc:
            cfg["hashcat"][plat] = hc

        pp = self.query_one("#cfg_prince_bin", Input).value.strip()
        if pp:
            cfg["princeprocessor"][plat] = pp

        out = self.query_one("#cfg_out_file", Input).value.strip()
        if out:
            cfg["default_output_file"] = out

        flags_raw = self.query_one("#cfg_def_flags", Input).value.strip()
        cfg["default_flags"] = flags_raw.split() if flags_raw else []

        wd = self.query_one("#cfg_warn_days", Input).value.strip()
        if wd.isdigit():
            cfg["warn_days"] = int(wd)

        save_config(cfg)
        self.dismiss(cfg)

    def action_discard(self) -> None:
        self.dismiss(None)

# ---------------------------------------------------------------------------
# TUI — Main App
# ---------------------------------------------------------------------------

_SEL   = "\u25cf "   # ● selected item marker
_UNSEL = "\u25cb "   # ○ unselected item marker


class HashcatTUI(App):
    """Hashcat TUI — interactive command builder."""

    CSS = """
    Screen { layout: vertical; }
    #main { height: 1fr; }
    #left   { width: 35%; border: solid green; }
    #middle { width: 30%; border: solid cyan;  }
    #right  { width: 35%; border: solid blue;  }
    #output_log { height: 10; border: solid yellow; }
    .sec { color: $accent; text-style: bold; margin-top: 1; }
    """

    BINDINGS = [
        Binding("r", "run",         "Run"),
        Binding("c", "copy",        "Copy"),
        Binding("h", "history",     "History"),
        Binding("e", "config",      "Config"),
        Binding("q", "quit",        "Quit"),
        # 🔥 Hashcat interactive controls
        Binding("s", "hc_status", "Status"),
        Binding("b", "hc_break", "Breakpoint"),
        Binding("p", "hc_pause", "Pause"),
        Binding("o", "hc_resume", "Resume"),
        Binding("x", "hc_quit", "Stop Hashcat"),
    ]

    def __init__(self) -> None:
        super().__init__()
        self._pty_master: int | None = None
        self._pty_slave: int | None = None
        self._current_proc: subprocess.Popen | None = None
        self.cfg: dict = load_config()

        # Selection state
        self._hash_file: str = ""
        self._mode: str = ""
        self._rules: set[str] = set()
        self._wordlists: set[str] = set()

        # Cached file indexes
        self._all_hash_files: list[str] = []
        self._all_rules: list[str] = []
        self._all_wordlists: list[str] = []

        # Active directory filter for hash file panel
        self._hash_dir_filter: str = ""   # empty → show all

        # Manual path entry mode for hash file
        self._manual_mode: bool = False

    # ---- compose ----

    def compose(self) -> ComposeResult:
        yield Header()

        with Horizontal(id="main"):

            # ──────────────────── LEFT: directories / hash files / mode ──────
            with VerticalScroll(id="left"):
                yield Static("Hash Directories", classes="sec")
                yield ListView(id="dir_list")

                yield Static("Hash Files  (Enter = select)", classes="sec")
                yield Input(placeholder="filter…", id="hash_filter")
                yield ListView(id="hash_list")

                yield Static("Hash Mode  (Enter = select)", classes="sec")
                yield Input(placeholder="filter modes…", id="mode_filter")
                yield ListView(id="mode_list")

            # ──────────────────── MIDDLE: rules / wordlists (multi-select) ───
            with VerticalScroll(id="middle"):
                yield Static("Rules  (Enter = toggle selection)", classes="sec")
                yield Input(placeholder="filter rules…", id="rule_filter")
                yield ListView(id="rule_list")

                yield Static("Wordlists  (Enter = toggle selection)", classes="sec")
                yield Input(placeholder="filter wordlists…", id="wl_filter")
                yield ListView(id="wl_list")

            # ──────────────────── RIGHT: options / summary / actions ─────────
            with VerticalScroll(id="right"):
                yield Static("Output File", classes="sec")
                yield Input(id="out_file", placeholder="master.txt")

                yield Static("Extra Hashcat Flags", classes="sec")
                yield Input(id="extra_flags", placeholder="e.g. --potfile-disable")

                yield Checkbox("Use PRINCE processor", id="use_prince")

                yield Static("PRINCE Arguments", classes="sec")
                yield Input(id="prince_args", placeholder="e.g. --pw-min=8 --pw-max=16")

                yield Static("PRINCE Input Wordlist (path)", classes="sec")
                yield Input(id="prince_input", placeholder="/path/to/wordlist.txt")

                yield Static("── Summary ─────────────────────────────────────", classes="sec")
                yield Static("", id="summary", markup=False)

                with Horizontal():
                    yield Button("\u25b6 Run  [r]", id="btn_run",  variant="success")
                    yield Button("\U0001f4cb Copy [c]", id="btn_copy", variant="primary")

        yield Log(id="output_log", highlight=True)
        yield Footer()

    # ---- mount: build indexes and populate all lists ----

    def on_mount(self) -> None:
        self._rebuild_indexes()
        self._populate_dirs()
        self._populate_hash_list()
        self._populate_mode_list()
        self._populate_rules()
        self._populate_wordlists()
        # Pre-fill output file from config
        self.query_one("#out_file", Input).value = self.cfg.get("default_output_file", "master.txt")
        self._update_summary()

    # ---- index builders ----

    def _rebuild_indexes(self) -> None:
        self._all_hash_files = list_hash_files(self.cfg)
        self._all_rules = list_rules(self.cfg)
        self._all_wordlists = list_wordlists(self.cfg)

    # ---- list populators ----

    def _populate_dirs(self) -> None:
        dl = self.query_one("#dir_list", ListView)
        dl.clear()
        dl.append(ListItem(Label("ALL"), name="__all__"))
        for d in self.cfg.get("hash_files_directories", []):
            dl.append(ListItem(Label(d), name=d))

    def _populate_hash_list(self, filt: str = "") -> None:
        hl = self.query_one("#hash_list", ListView)
        hl.clear()
        files = (
            [f for f in self._all_hash_files if f.startswith(self._hash_dir_filter)]
            if self._hash_dir_filter else self._all_hash_files
        )
        for f in files:
            if filt.lower() in f.lower():
                hl.append(ListItem(Label(Path(f).name), name=f))
        hl.append(ListItem(Label("\u270e Enter path manually\u2026"), name="__manual__"))

    def _populate_mode_list(self, filt: str = "") -> None:
        ml = self.query_one("#mode_list", ListView)
        ml.clear()
        modes = sorted(self.cfg.get("hash_modes", {}).items(), key=lambda x: int(x[0]))
        for k, v in modes:
            label = f"{k:>6}  {v}"
            if filt.lower() in label.lower():
                ml.append(ListItem(Label(label), name=k))

    def _populate_rules(self, filt: str = "") -> None:
        rl = self.query_one("#rule_list", ListView)
        rl.clear()
        for f in self._all_rules:
            if filt.lower() in f.lower():
                prefix = _SEL if f in self._rules else _UNSEL
                rl.append(ListItem(Label(f"{prefix}{Path(f).name}"), name=f))

    def _populate_wordlists(self, filt: str = "") -> None:
        wl = self.query_one("#wl_list", ListView)
        wl.clear()
        for f in self._all_wordlists:
            if filt.lower() in f.lower():
                prefix = _SEL if f in self._wordlists else _UNSEL
                wl.append(ListItem(Label(f"{prefix}{Path(f).name}"), name=f))

    # ---- event handlers ----

    def on_input_changed(self, event: Input.Changed) -> None:
        wid = event.input.id
        val = event.value
        if wid == "hash_filter" and not self._manual_mode:
            self._populate_hash_list(val)
        elif wid == "mode_filter":
            self._populate_mode_list(val)
        elif wid == "rule_filter":
            self._populate_rules(val)
        elif wid == "wl_filter":
            self._populate_wordlists(val)
        elif wid in ("out_file", "extra_flags", "prince_args", "prince_input"):
            self._update_summary()

    def on_checkbox_changed(self, _: Checkbox.Changed) -> None:
        self._update_summary()

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        lv_id = event.list_view.id
        name = event.item.name or ""

        if lv_id == "dir_list":
            if name == "__all__":
                self._hash_dir_filter = ""
            else:
                self._hash_dir_filter = name
            self._hash_file = ""
            self._manual_mode = False
            filt = self.query_one("#hash_filter", Input)
            filt.placeholder = "filter…"
            filt.value = ""
            self._populate_hash_list()

        elif lv_id == "hash_list":
            if name == "__manual__":
                # Repurpose hash_filter as a path input
                inp = self.query_one("#hash_filter", Input)
                inp.value = ""
                inp.placeholder = "Type full path, then press Enter"
                self._manual_mode = True
            else:
                self._hash_file = name
                self._manual_mode = False

        elif lv_id == "mode_list":
            self._mode = name

        elif lv_id == "rule_list":
            # Toggle
            if name in self._rules:
                self._rules.discard(name)
            else:
                self._rules.add(name)
            filt = self.query_one("#rule_filter", Input).value
            self._populate_rules(filt)
            self._update_summary()
            return  # skip redundant summary call below

        elif lv_id == "wl_list":
            # Toggle
            if name in self._wordlists:
                self._wordlists.discard(name)
            else:
                self._wordlists.add(name)
            filt = self.query_one("#wl_filter", Input).value
            self._populate_wordlists(filt)
            self._update_summary()
            return

        self._update_summary()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Handle Enter in the hash_filter when in manual-path mode."""
        if event.input.id == "hash_filter" and self._manual_mode:
            path = event.value.strip().strip('"')
            if path:
                self._hash_file = path
            inp = event.input
            inp.value = ""
            inp.placeholder = "filter…"
            self._manual_mode = False
            self._populate_hash_list()
            self._update_summary()

    # ---- command building ----

    def _build_command(self) -> str | None:
        if not self._hash_file or not self._mode:
            return None
        use_prince = self.query_one("#use_prince", Checkbox).value
        out = self.query_one("#out_file", Input).value.strip()
        output_file = out or self.cfg.get("default_output_file", "master.txt")
        return build_hashcat_command(
            cfg=self.cfg,
            hash_file=self._hash_file,
            mode=self._mode,
            wordlists=sorted(self._wordlists),
            rules=sorted(self._rules),
            output_file=output_file,
            extra_flags=self.query_one("#extra_flags", Input).value.strip(),
            use_prince=use_prince,
            prince_args=self.query_one("#prince_args", Input).value.strip(),
            prince_input=self.query_one("#prince_input", Input).value.strip(),
        )

    # ---- summary ----

    def _update_summary(self) -> None:
        use_prince = self.query_one("#use_prince", Checkbox).value
        out = self.query_one("#out_file", Input).value.strip()
        output_file = out or self.cfg.get("default_output_file", "master.txt")

        lines = [
            f"FILE  : {self._hash_file or '(none)'}",
            f"MODE  : {self._mode or '(none)'}",
            f"RULES : {len(self._rules)} selected",
            f"WL    : {len(self._wordlists)} selected",
            f"OUT   : {output_file}",
            f"PRINCE: {'yes' if use_prince else 'no'}",
        ]
        cmd = self._build_command()
        lines.append("")
        lines.append("CMD:")
        lines.append(cmd if cmd else "[!] Incomplete — select file and mode")

        self.query_one("#summary", Static).update("\n".join(lines))

    # ---- actions ----

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn_run":
            self.action_run()
        elif event.button.id == "btn_copy":
            self.action_copy()

    def action_copy(self) -> None:
        log = self.query_one("#output_log", Log)
        cmd = self._build_command()
        if not cmd:
            log.write_line("[!] Incomplete — select hash file and mode first.")
            return
        if _HAS_PYPERCLIP:
            try:
                _pyperclip.copy(cmd)
                log.write_line("[+] Command copied to clipboard.")
            except Exception as exc:
                log.write_line(f"[!] Clipboard error: {exc}")
        else:
            log.write_line("[!] pyperclip not installed.  Command:")
            log.write_line(cmd)

    def action_run(self) -> None:
        log = self.query_one("#output_log", Log)
        cmd = self._build_command()
        if not cmd:
            log.write_line("[!] Incomplete — select hash file and mode first.")
            return

        warn_days = self.cfg.get("warn_days", 7)
        recent = check_recent(
            hash_file=self._hash_file,
            mode=self._mode,
            wordlists=sorted(self._wordlists),
            rules=sorted(self._rules),
            extra_flags=self.query_one("#extra_flags", Input).value,
            use_prince=self.query_one("#use_prince", Checkbox).value,
            prince_args=self.query_one("#prince_args", Input).value,
            prince_input=self.query_one("#prince_input", Input).value,
            warn_days=warn_days,
        )
        if recent:
            def _after_warn(proceed: bool | None) -> None:
                if proceed:
                    self._do_run(cmd)
            self.push_screen(WarnDialog(recent, warn_days), _after_warn)
        else:
            self._do_run(cmd)

    # =============================
    # INTERACTIVE INPUT
    # =============================

    def _send_to_hashcat(self, key: str) -> None:
        if self._pty_master is not None:
            import os
            try:
                os.write(self._pty_master, key.encode())
            except Exception as e:
                self.query_one("#output_log", Log).write_line(f"[!] Input error: {e}")

    def action_hc_status(self): self._send_to_hashcat("s")
    def action_hc_break(self):  self._send_to_hashcat("b")
    def action_hc_pause(self):  self._send_to_hashcat("p")
    def action_hc_resume(self): self._send_to_hashcat("r")
    def action_hc_quit(self):   self._send_to_hashcat("q")

    def action_hc_force_kill(self):
        if self._current_proc:
            self._current_proc.kill()

    def _do_run(self, cmd: str) -> None:
        use_prince = self.query_one("#use_prince", Checkbox).value

        record_command(
            cmd=cmd,
            hash_file=self._hash_file,
            mode=self._mode,
            wordlists=sorted(self._wordlists),
            rules=sorted(self._rules),
            extra_flags=self.query_one("#extra_flags", Input).value,
            use_prince=self.query_one("#use_prince", Checkbox).value,
            prince_args=self.query_one("#prince_args", Input).value,
            prince_input=self.query_one("#prince_input", Input).value,
        )

        log = self.query_one("#output_log", Log)
        log.write_line(f"[*] Executing (PTY): {cmd}")

        self._stream_command(cmd, use_prince)

    @work(thread=True)
    def _stream_command(self, cmd: str, use_prince: bool) -> None:
        log = self.query_one("#output_log", Log)

        try:
            # Create PTY
            master_fd, slave_fd = pty.openpty()
            rows, cols = 40, 120
            fcntl.ioctl(slave_fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
            self._pty_master = master_fd
            self._pty_slave = slave_fd

            shell = _needs_shell(cmd, use_prince)
            shell_bin = "/bin/bash" if shell and _PLATFORM != "windows" else None

            proc = subprocess.Popen(
                cmd if shell else shlex.split(cmd),
                shell=shell,
                executable=shell_bin,
                stdin=slave_fd,
                stdout=slave_fd,
                stderr=slave_fd,
                close_fds=True,
            )

            self._current_proc = proc

            # Non-blocking read loop
            while True:
                r, _, _ = select.select([master_fd], [], [], 0.1)
                if master_fd in r:
                    try:
                        data = os.read(master_fd, 4096)
                        if not data:
                            break
                        text = data.decode(errors="ignore")
                        self.call_from_thread(log.write, text)
                    except OSError:
                        break

                if proc.poll() is not None:
                    break

            proc.wait()

            self.call_from_thread(
                log.write_line,
                f"\n[+] Process exited with code {proc.returncode}"
            )

        except Exception as exc:
            self.call_from_thread(log.write_line, f"[!] Error: {exc}")

        finally:
            if self._pty_master is not None:
                os.close(self._pty_master)
            if self._pty_slave is not None:
                os.close(self._pty_slave)
            self._pty_master = None
            self._pty_slave = None
            self._current_proc = None
        
    def action_history(self) -> None:
        self.push_screen(HistoryScreen(self.cfg))

    def action_config(self) -> None:
        def _after_config(new_cfg: dict | None) -> None:
            if isinstance(new_cfg, dict):
                self.cfg = new_cfg
                self._rebuild_indexes()
                # Purge selections that no longer exist after config change
                self._rules &= set(self._all_rules)
                self._wordlists &= set(self._all_wordlists)
                self._populate_dirs()
                self._populate_hash_list()
                self._populate_mode_list()
                self._populate_rules()
                self._populate_wordlists()
                out_inp = self.query_one("#out_file", Input)
                if not out_inp.value:
                    out_inp.value = self.cfg.get("default_output_file", "master.txt")
                self._update_summary()

        self.push_screen(ConfigScreen(self.cfg), _after_config)

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    if sys.version_info < (3, 10):
        sys.exit(
            "[!] Python 3.10 or newer is required.\n"
            "    Ubuntu 20.04: sudo apt install python3.10\n"
            "    Ubuntu 22.04+ / Kali: already ships 3.10+"
        )
    HashcatTUI().run()
