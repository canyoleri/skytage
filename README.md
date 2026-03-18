# Skytage

A Chrome extension that detects, tracks, and analyzes cloud storage buckets on visited websites.

## Features

- **Cloud Storage Detection** — Scans page source, inline scripts, external CSS/JS files, and live network requests as you browse
- **DNS CNAME Discovery** — Detects custom domains (e.g. `assets.company.com`) that point to cloud storage buckets via CNAME records
- **Cross-Site Bucket Tracking** — Tracks which buckets appear across multiple sites, useful for identifying supply chain or shadow IT exposure
- **Misconfiguration Checker** — Tests whether detected buckets have public listing enabled and parses the listing for sensitive files
- **Sensitive File Detection** — Identifies high-risk files in public buckets (credentials, keys, database dumps, config files, etc.)
- **Subdomain Takeover Detection** — Flags buckets that no longer exist but still have active DNS records
- **Check History** — Tracks the last 10 check results per bucket with timestamps
- **Export** — Export findings as `.txt`, `.json`, or `.csv`

## Supported Providers

| Provider | Detection | Listing Check |
|---|---|---|
| AWS S3 | Yes | Yes |
| Azure Blob Storage | Yes | Yes (container-level) |
| Google Cloud Storage | Yes | Yes |
| DigitalOcean Spaces | Yes | Yes |
| Cloudflare R2 | Yes | No (no standard endpoint) |

## Installation

1. Clone or download this repository
2. Open `chrome://extensions` in Chrome
3. Enable **Developer mode** (top right)
4. Click **Load unpacked** and select the `code/` folder

## Usage

Click the Skytage icon in your toolbar after visiting any website. Findings are grouped under two tabs:

- **By Site** — Detected URLs grouped by domain, with public/private status badges
- **Buckets** — All unique buckets, sorted by cross-site presence. Use **Check All** to run misconfiguration checks.

Each bucket in the Buckets tab shows:
- Public listing status (Public / Private / Unknown)
- Takeover Risk badge — if the bucket DNS record is active but the bucket does not exist
- Sensitive Files badge — count of high-risk filenames found in the listing
- CNAME badge — if the bucket was discovered via a custom domain
- Check history timeline

## Detection Sources

Skytage detects cloud storage URLs from multiple sources:

1. **Page HTML** — Full DOM source on load and on dynamic content changes (MutationObserver)
2. **External resources** — Linked CSS and JavaScript files (up to 2 MB each)
3. **Network requests** — All browser requests intercepted via `chrome.webRequest`, including XHR, fetch, and lazy-loaded resources
4. **DNS CNAME lookups** — External hostnames on the page are checked against Google DNS-over-HTTPS for CNAME records pointing to cloud storage

