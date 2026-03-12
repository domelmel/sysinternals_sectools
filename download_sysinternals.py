#!/usr/bin/env python3
"""
Pobieranie narzedzi Sysinternals do pracy offline (np. na pendrive).

Domyslnie skrypt pobiera:
- Top 10 narzedzi administratorskich
- dodatkowe narzedzia security

Uzycie:
  python3 download_sysinternals.py
  python3 download_sysinternals.py --only top10
  python3 download_sysinternals.py --only security
    python3 download_sysinternals.py --dest ./downloads/pakiet_sysinternals
"""

from __future__ import annotations

import argparse
import shutil
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

BASE_URL = "https://download.sysinternals.com/files"
LIVE_BASE_URL = "https://live.sysinternals.com"
TIMEOUT_SECONDS = 45


@dataclass(frozen=True)
class Tool:
    name: str
    filename: str
    note: str = ""

    @property
    def url(self) -> str:
        return f"{BASE_URL}/{self.filename}"

    @property
    def fallback_filenames(self) -> tuple[str, ...]:
        # Niektore pliki Sysinternals maja warianty wielkosci liter w nazwie.
        variants = {self.filename, self.filename.lower(), self.filename.upper()}
        manual_map = {
            "PsTools.zip": ("PSTools.zip", "pstools.zip"),
            "BgInfo.exe": ("Bginfo.exe", "bginfo.exe"),
        }
        for item in manual_map.get(self.filename, ()):
            variants.add(item)
        return tuple(variants)

    @property
    def candidate_urls(self) -> tuple[str, ...]:
        urls: list[str] = []
        for filename in self.fallback_filenames:
            urls.append(f"{BASE_URL}/{filename}")
            urls.append(f"{LIVE_BASE_URL}/{filename}")
        return tuple(dict.fromkeys(urls))


TOP10_TOOLS: tuple[Tool, ...] = (
    Tool("Process Explorer", "ProcessExplorer.zip"),
    Tool("Process Monitor", "ProcessMonitor.zip"),
    Tool("Autoruns", "Autoruns.zip"),
    Tool("PsExec (w pakiecie PsTools)", "PsTools.zip", "Zawiera m.in. PsExec, PsList, PsKill"),
    Tool("TCPView", "TCPView.zip"),
    Tool("RAMMap", "RAMMap.zip"),
    Tool("Disk2Vhd", "Disk2vhd.zip"),
    Tool("Sysmon", "Sysmon.zip"),
    Tool("BgInfo", "BgInfo.exe"),
    Tool("AccessChk", "AccessChk.zip"),
)

SECURITY_EXTRA_TOOLS: tuple[Tool, ...] = (
    Tool("Sigcheck", "Sigcheck.zip", "Sprawdzanie podpisow i reputacji plikow"),
    Tool("Handle", "Handle.zip", "Sprawdza, ktory proces trzyma uchwyt do pliku"),
    Tool("ProcDump", "Procdump.zip", "Zrzuty procesu do analizy incydentow"),
    Tool("Strings", "Strings.zip", "Szybki rekonesans artefaktow tekstowych w plikach"),
    Tool("VMMap", "VMMap.zip", "Analiza mapowania pamieci procesu"),
    Tool("WinObj", "WinObj.zip", "Przeglad obiektow jadra/systemu"),
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Pobierz narzedzia Sysinternals do folderu lokalnego (portable)."
    )
    parser.add_argument(
        "--dest",
        default="downloads/sysinternals_portable",
        help="Katalog docelowy (domyslnie: ./downloads/sysinternals_portable)",
    )
    parser.add_argument(
        "--only",
        choices=("top10", "security", "all"),
        default="all",
        help="Co pobrac: top10, security albo all (domyslnie: all)",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Nadpisz istniejace pliki",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="Wyswietl liste narzedzi i zakoncz",
    )
    return parser.parse_args()


def print_toolset(title: str, tools: Iterable[Tool]) -> None:
    print(f"\n{title}")
    for idx, tool in enumerate(tools, start=1):
        extra = f" [{tool.note}]" if tool.note else ""
        print(f"  {idx:>2}. {tool.name} -> {tool.filename}{extra}")


def ensure_clean_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def download_file(url: str, dest: Path, force: bool) -> tuple[str, str]:
    if dest.exists() and not force:
        return "SKIP", url

    tmp_path = dest.with_suffix(dest.suffix + ".part")
    try:
        with urllib.request.urlopen(url, timeout=TIMEOUT_SECONDS) as response:
            with tmp_path.open("wb") as out_file:
                shutil.copyfileobj(response, out_file)
        tmp_path.replace(dest)
        return "OK", url
    except urllib.error.HTTPError as exc:
        if tmp_path.exists():
            tmp_path.unlink(missing_ok=True)
        return f"HTTP {exc.code}", url
    except urllib.error.URLError as exc:
        if tmp_path.exists():
            tmp_path.unlink(missing_ok=True)
        return f"URLERR {exc.reason}", url
    except Exception as exc:  # noqa: BLE001
        if tmp_path.exists():
            tmp_path.unlink(missing_ok=True)
        return f"ERR {exc}", url


def download_tool(tool: Tool, group_dir: Path, force: bool) -> tuple[str, str]:
    dest = group_dir / tool.filename
    if dest.exists() and not force:
        return "SKIP", tool.url

    last_status = "ERR unknown"
    last_url = tool.url
    for candidate_url in tool.candidate_urls:
        status, used_url = download_file(candidate_url, dest, force=force)
        if status in ("OK", "SKIP"):
            return status, used_url
        last_status = status
        last_url = used_url

    return last_status, last_url


def run_download(group_name: str, tools: Iterable[Tool], base_dir: Path, force: bool) -> tuple[int, int, int]:
    group_dir = base_dir / group_name
    ensure_clean_dir(group_dir)

    ok = 0
    skipped = 0
    failed = 0

    print(f"\n=== Pobieranie: {group_name} -> {group_dir} ===")
    for tool in tools:
        dest = group_dir / tool.filename
        status, used_url = download_tool(tool, group_dir, force=force)
        if status == "OK":
            ok += 1
            print(f"[OK]   {tool.name}: {used_url}")
        elif status == "SKIP":
            skipped += 1
            print(f"[SKIP] {tool.name}: plik juz istnieje ({dest.name})")
        else:
            failed += 1
            print(f"[FAIL] {tool.name}: {used_url} -> {status}")

    return ok, skipped, failed


def main() -> int:
    args = parse_args()
    dest_dir = Path(args.dest).resolve()

    print_toolset("Top 10 Sysinternals", TOP10_TOOLS)
    print_toolset("Dodatkowe narzedzia security", SECURITY_EXTRA_TOOLS)

    if args.list:
        return 0

    ensure_clean_dir(dest_dir)

    total_ok = 0
    total_skipped = 0
    total_failed = 0

    if args.only in ("top10", "all"):
        ok, skipped, failed = run_download("top10", TOP10_TOOLS, dest_dir, args.force)
        total_ok += ok
        total_skipped += skipped
        total_failed += failed

    if args.only in ("security", "all"):
        ok, skipped, failed = run_download("security", SECURITY_EXTRA_TOOLS, dest_dir, args.force)
        total_ok += ok
        total_skipped += skipped
        total_failed += failed

    print("\n=== Podsumowanie ===")
    print(f"Docelowy katalog: {dest_dir}")
    print(f"Pobrane:          {total_ok}")
    print(f"Pominiete:        {total_skipped}")
    print(f"Bledy:            {total_failed}")

    if total_failed:
        print("\nCzesc plikow nie zostala pobrana. Uruchom ponownie z --force po sprawdzeniu lacza.")
        return 2

    print("\nGotowe. Katalog mozna skopiowac 1:1 na pendrive.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
