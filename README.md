# Owleye

A fast, async VulnHub scraper built to feed machine data into [Zertana](#).

Owleye crawls [VulnHub](https://www.vulnhub.com), collects machine metadata (difficulty, author, download links, checksums), and saves everything to a local JSON database that Zertana consumes.

---

## Requirements

- Python 3.14+
- [uv](https://docs.astral.sh/uv/)

## Installation

```bash
git clone https://github.com/yourname/owleye
cd owleye
uv sync
```

## Usage

```bash
# Scrape everything
uv run owleye

# Limit to 10 pages, 8 concurrent requests
uv run owleye --max-pages 10 --concurrency 8

# Custom output path
uv run owleye --output ~/zertana/machines.json
```

| Flag              | Default                              | Description                   |
| ----------------- | ------------------------------------ | ----------------------------- |
| `--max-pages N`   | all                                  | Stop after N listing pages    |
| `--concurrency N` | 6                                    | Parallel detail-page requests |
| `--output PATH`   | `~/.config/zertana/machines_db.json` | Output JSON path              |

The database is saved incrementally — if interrupted, re-running will resume from where it left off.

## Output format

```json
{
  "metadata": {
    "last_updated": "2026-03-16T12:00:00+00:00",
    "total_targets": 542,
    "source": "https://www.vulnhub.com"
  },
  "targets": [
    {
      "id": "example/1",
      "name": "Example: 1",
      "difficulty": "Beginner",
      "release_date": "01 Jan 2024",
      "author": "SomeAuthor",
      "description": "...",
      "download_info": {
        "url": "https://...",
        "format": "OVA",
        "size": "1.2 GB",
        "checksums": {
          "md5": "abc123",
          "sha1": "def456"
        }
      }
    }
  ]
}
```

## Disclaimer

Owleye scrapes publicly available data from VulnHub for personal, ethical hacking lab use only. Please respect VulnHub's terms of service.
