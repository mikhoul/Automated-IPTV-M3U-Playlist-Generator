# Automated IPTV M3U Playlist Generator (via GitHub Actions or Local)

A self-contained Python 3 application and GitHub Actions workflow that **automatically discovers, validates, deduplicates, and exports live TV streaming links** (IPTV / HLS) for a given country or custom source list.  The project started as a simple playlist grabber but has evolved into a full-featured pipeline capable of handling very large source files (>50 000 lines), extracting streams from HTML pages, and producing production-ready playlists in several formats.

**👉** **Important:** This version is configurated to pull mainly french channels. You can configure it for any URL/language with the flag _**"source_urls"**_ in the code.

---

## ✨ Key Features

| Category                               | Capability |
|----------------------------------------|------------|
| **Playlist ingestion**                 | • Streams M3U files line-by-line to keep memory usage low<br>• Recursively follows HTTP, HTTPS, and HTML pages to locate additional *.m3u8* links |
| **Smart parsing**                      | • Robust `#EXTINF` attribute extraction (logo, group-title, language, resolution, etc.)<br>• Cuisine/Zeste and other special-case tag fixes |
| **Fast validation**                    | • 15-thread `ThreadPoolExecutor` (configurable) <br>• HEAD → GET fall-back with protocol switching <br>• HLS‐aware probe for real playlists <br>• Geo-blocking detection (403) |
| **Deduplication & ranking**            | • URL + fuzzy title check (Jaccard similarity) <br>• Keeps best resolution (4K > 1080p > 720p …) |
| **Filtering**                          | • Excludes 20+ predefined countries / spam categories <br>• Skip non-HTTP URLs and offline/test/demo groups |
| **Metadata enrichment**                | • Automatic language guess (en / fr) <br>• Quality & resolution tags <br>• Server geolocation stamp for audits |
| **Multi-format export**                | • `LiveTV.m3u` (fully tagged) <br>• `LiveTV.txt` (human readable) <br>• `LiveTV.json` (rich metadata + stats) <br>• `LiveTV` (compact custom JSON) |
| **Colored logging**                    | • ANSI colour formatter with collision-free palette for SUCCESS / INACTIVE / GEO-BLOCKED, etc. |
| **Statistics & reports**               | • Auto-generated processing report summarising channels, groups, failures, timings |
| **Extensible config**                  | • All tunables exposed via a single `config` dict (workers, retries, quality order …) |

> All of the above are implemented in a single file – [`TV-Mikhoul.py`](BugsfreeMain/TV-Mikhoul.py) – making deployment and CI very easy.[1]

---

## 🔧 How It Works

```
┌────────────┐      1. Fetch each source (M3U / HTML)
│  Sources   │──┐  2. Optional HTML scraping discovers extra .m3u8 links
└────────────┘  │
                ▼
        ┌──────────────────┐
        │   Parser &       │  — line-streaming, EXTINF attr extraction,
        │  Pre-filtering   │    cuisine detection, URL cleaning
        └──────────────────┘
                ▼
        ┌──────────────────┐
        │ Deduplication &  │  — hash + fuzzy title, quality ranking,
        │  Group sorting   │    skip excluded categories
        └──────────────────┘
                ▼
        ┌──────────────────┐
        │  Concurrent Link │  — HEAD→GET, HLS probe, geo-block flag,
        │   Validation     │    cache + retry
        └──────────────────┘
                ▼
        ┌──────────────────┐
        │    Exporters     │  — M3U · TXT · JSON · custom
        └──────────────────┘
                ▼
        ┌──────────────────┐
        │   Reports &      │  — stats, error   breakdown, timing
        │   GitHub Action  │    summary
        └──────────────────┘
```

---

## 🚀 Quick Start

### 1. Clone & install deps
```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt   # requests, beautifulsoup4, pytz, etc.
```

### 2. Run locally
```bash
python TV-Mikhoul.py            # processes default source list
```

The resulting playlists are written under `LiveTV/<Country>/` (default: *LiveTV/Mikhoul*).

### 3. Run via GitHub Actions
The repository ships with **`update-indexes.yml`** which:
1. Executes the collector every 24 hours.
2. Pushes artefacts so the latest playlists are always available.

---

## ⚙️ Important Configuration Flags
| Variable            | Default | Description |
|---------------------|---------|-------------|
| `max_workers`       | `15`    | Threads used during validation |
| `request_timeout`   | `12` s | Per-request network timeout |
| `max_retries`       | `2`     | Network retries with exponential back-off |
| `excluded_groups`   | list    | Groups or countries to skip |
| `quality_preferences` | `["4K", "1080p", …]` | Order used when keeping best duplicate |
| `enable_deduplication` | `True` | Toggle duplicate removal |
| `enable_quality_sorting` | `True` | Toggle resolution-first sort |


There is many more flags/options in the code they are well commented and easy to understand.
Change any of these by passing a `config` dict to the `M3UCollector` constructor or editing the **`main()`** section.

---

## 📂 Output Tree (example)
```
LiveTV/
└── Mikhoul/
    ├── LiveTV.m3u
    ├── LiveTV.txt
    ├── LiveTV.json
    ├── LiveTV           # custom
    ├── processing_report.txt
    └── cache/ …
```
Each format is fully self-contained and ready for players such as **VLC**, **Kodi**, **OTT Navigator**, **Tivimate** or **Jellyfin**.

---

## 🛠️ Extending the Collector
1. **Add new sources** – append URLs to `source_urls` list in `main()`.
2. **Custom validation logic** – override `validate_hls_stream` or `validate_regular_url`.
3. **New exporters** – implement `export_<format>()` and register in `export_all_formats()`.
4. **Use as a library** – import `M3UCollector` and call `process_sources()` from your own code.

---

## 🤝 Contributing
Pull requests are welcome — see `CONTRIBUTING.md` for linting rules and commit message conventions.  Bug reports can be opened via GitHub Issues.

---

## 📜 License
This project is released under the **MIT License**.  See `LICENSE` for details.
