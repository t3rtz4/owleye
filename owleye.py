import asyncio
import argparse
import json
from pathlib import Path
from datetime import datetime, timezone

import httpx
from bs4 import BeautifulSoup
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn

console = Console()

BASE_URL = "https://www.vulnhub.com"
HEADERS = {"User-Agent": "Owleye-Scout/5.0 (Ethical Hacking Lab Builder)"}
DEFAULT_DB_PATH = Path.home() / ".config" / "zertana" / "machines_db.json"

# VulnHub pages 60+ redirect to page 59
# this is the true last valid page.
VULNHUB_LAST_PAGE = 59

def load_existing_db(db_path: Path) -> tuple[dict, set]:
    if db_path.exists():
        try:
            with open(db_path) as f:
                data = json.load(f)
            known_ids = {m["id"] for m in data.get("targets", [])}
            console.print(
                f"[cyan][~] Resuming: {len(known_ids)} machines already in DB.[/cyan]"
            )
            return data, known_ids
        except (json.JSONDecodeError, KeyError):
            console.print("[yellow][!] Existing DB corrupted — starting fresh.[/yellow]")

    return {"metadata": {}, "targets": []}, set()


def save_db(db_path: Path, machines: list[dict]) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    db = {
        "metadata": {
            "last_updated": datetime.now(timezone.utc).isoformat(),
            "total_targets": len(machines),
            "source": BASE_URL,
        },
        "targets": machines,
    }
    tmp = db_path.with_suffix(".tmp")
    with open(tmp, "w") as f:
        json.dump(db, f, indent=4)
    tmp.replace(db_path)


@retry(
    retry=retry_if_exception_type((httpx.HTTPError, httpx.TimeoutException)),
    wait=wait_exponential(multiplier=1, min=2, max=30),
    stop=stop_after_attempt(4),
    reraise=True,
)
async def fetch(client: httpx.AsyncClient, url: str) -> str:
    resp = await client.get(url, timeout=20.0)
    resp.raise_for_status()
    return resp.text


def parse_card(card, base_url: str) -> dict | None:
    title_tag = card.select_one(".card-title a")
    if not title_tag:
        return None

    return {
        "name": title_tag.text.strip(),
        "url": base_url + title_tag["href"],
        "id": title_tag["href"].strip("/"),
        "release_date": (
            card.select_one(".card-date a").text.strip()
            if card.select_one(".card-date a")
            else "Unknown"
        ),
        "author": (
            card.select_one(".card-author a").text.strip()
            if card.select_one(".card-author a")
            else "Unknown"
        ),
    }


def parse_entry_page(html: str) -> dict:
    soup = BeautifulSoup(html, "html.parser")
    result: dict = {
        "download_url": None,
        "format": None,
        "file_size": "Unknown",
        "checksums": {"md5": "Unknown", "sha1": "Unknown"},
    }

    fileinfo = soup.find("div", id="fileinfo")
    if fileinfo:
        for li in fileinfo.find_all("li"):
            text = li.text
            if "File size:" in text:
                result["file_size"] = text.split("File size:")[1].strip()
            elif "MD5:" in text:
                result["checksums"]["md5"] = text.split("MD5:")[1].strip()
            elif "SHA1:" in text:
                result["checksums"]["sha1"] = text.split("SHA1:")[1].strip()

    download_panel = soup.find("div", id="download")
    if download_panel:
        links = download_panel.find_all("a", href=True)
        for ext, fmt in [(".ova", "OVA"), (".vmdk", "VMDK"), (".zip", "ZIP"), (".7z", "7Z")]:
            for a in links:
                if ext in a["href"].lower():
                    result["download_url"] = a["href"]
                    result["format"] = fmt
                    break
            if result["download_url"]:
                break

    return result

async def scrape_machine(
    client: httpx.AsyncClient,
    card_info: dict,
    semaphore: asyncio.Semaphore,
    progress,
    task_id,
) -> dict | None:
    async with semaphore:
        try:
            html = await fetch(client, card_info["url"])
            details = parse_entry_page(html)

            if not details["download_url"]:
                return None

            machine = {
                "id": card_info["id"],
                "name": card_info["name"],
                "release_date": card_info["release_date"],
                "author": card_info["author"],
                "download_info": {
                    "url": details["download_url"],
                    "format": details["format"],
                    "size": details["file_size"],
                    "checksums": details["checksums"],
                },
            }
            progress.advance(task_id)
            return machine
        except Exception as e:
            console.print(f"[red]  [x] Failed: {card_info['name']} — {e}[/red]")
            return None


async def scrape_page(
    client: httpx.AsyncClient, page_num: int
) -> list[dict]:
    url = f"{BASE_URL}/?page={page_num}"
    try:
        html = await fetch(client, url)
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            return []
        raise

    soup = BeautifulSoup(html, "html.parser")
    cards = soup.find_all("div", class_="card")
    return [c for raw in cards if (c := parse_card(raw, BASE_URL))]


async def run(max_pages: int | None, concurrency: int, db_path: Path) -> None:
    console.print("[bold green][*] Owleye Scout v5.0 — Full Spectrum Async Recon[/bold green]\n")

    # Guard against VulnHub's redirect bug: pages 60+ silently redirect to page 59,
    # which would cause infinite scraping of duplicate data.
    effective_max = min(max_pages, VULNHUB_LAST_PAGE) if max_pages else VULNHUB_LAST_PAGE
    if max_pages and max_pages > VULNHUB_LAST_PAGE:
        console.print(
            f"[yellow][!] Requested {max_pages} pages, but VulnHub only has {VULNHUB_LAST_PAGE} "
            f"valid pages (pages 60+ redirect to page 59). Capping at {VULNHUB_LAST_PAGE}.[/yellow]"
        )

    existing_db, known_ids = load_existing_db(db_path)
    all_machines: list[dict] = existing_db.get("targets", [])

    semaphore = asyncio.Semaphore(concurrency)

    async with httpx.AsyncClient(headers=HEADERS, follow_redirects=True) as client:
        page_num = 1
        new_count = 0

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("{task.completed} machines saved"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            save_task = progress.add_task("[cyan]Scraping...", total=None)

            try:
                while True:
                    if page_num > effective_max:
                        console.print(
                            f"[yellow][!] Reached page limit ({effective_max}). Stopping.[/yellow]"
                        )
                        break

                    progress.update(save_task, description=f"[cyan]Page {page_num}/{effective_max}...")
                    cards = await scrape_page(client, page_num)

                    if not cards:
                        console.print(
                            f"[yellow][!] No cards on page {page_num}. Sweep complete.[/yellow]"
                        )
                        break

                    new_cards = [c for c in cards if c["id"] not in known_ids]
                    skipped = len(cards) - len(new_cards)
                    if skipped:
                        console.print(f"  [dim]Skipped {skipped} already-known machines.[/dim]")

                    if new_cards:
                        tasks = [
                            scrape_machine(client, card, semaphore, progress, save_task)
                            for card in new_cards
                        ]
                        results = await asyncio.gather(*tasks)

                        for machine in results:
                            if machine:
                                all_machines.append(machine)
                                known_ids.add(machine["id"])
                                new_count += 1

                        save_db(db_path, all_machines)

                    page_num += 1
                    await asyncio.sleep(0.5)

            except KeyboardInterrupt:
                console.print("\n[bold yellow][!] Interrupted. Saving intel...[/bold yellow]")

    save_db(db_path, all_machines)
    console.print(
        f"\n[bold green][+] Done. {new_count} new machines added "
        f"({len(all_machines)} total) → {db_path}[/bold green]"
    )

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Owleye Scout — async VulnHub machine database builder"
    )
    parser.add_argument(
        "--max-pages",
        type=int,
        default=VULNHUB_LAST_PAGE,
        metavar="N",
        help=f"Stop after N listing pages (default: {VULNHUB_LAST_PAGE}, the last valid VulnHub page — "
             f"pages 60+ redirect to page 59 causing infinite loops)",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=6,
        metavar="N",
        help="Max simultaneous detail page requests (default: 6)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_DB_PATH,
        metavar="PATH",
        help=f"Output JSON path (default: {DEFAULT_DB_PATH})",
    )
    args = parser.parse_args()

    asyncio.run(run(args.max_pages, args.concurrency, args.output))


if __name__ == "__main__":
    main()
