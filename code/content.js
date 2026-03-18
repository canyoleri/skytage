// content.js
const patterns = [
  {
    name: 'Azure Blob',
    pattern: /([a-z0-9-]+)\.blob\.core\.windows\.net(?:\/[^\s"'<>]*)?/g
  },
  {
    name: 'AWS S3',
    pattern: /([a-zA-Z0-9-\.]+)\.s3(?:[.-]([a-z0-9-]+))?\.amazonaws\.com(?:\/[^\s"'<>]*)?/g
  },
  {
    name: 'Google Cloud Storage',
    pattern: /([a-zA-Z0-9\.\-_]+)\.storage\.googleapis\.com(?:\/[^\s"'<>]*)?/g
  },
  {
    name: 'DigitalOcean Spaces',
    pattern: /([a-z0-9-]+)\.(?:[a-z0-9-]+\.)?digitaloceanspaces\.com(?:\/[^\s"'<>]*)?/g
  },
  {
    name: 'Cloudflare R2',
    pattern: /([a-z0-9-]+)\.r2\.(?:[a-z0-9-]+\.)?cloudflare\.com(?:\/[^\s"'<>]*)?/g
  }
];

function scanContent(content) {
  const seenUrls = new Set();
  const allMatches = [];

  patterns.forEach(provider => {
    const matches = content.match(provider.pattern) || [];
    matches.forEach(url => {
      const normalizedUrl = url.toLowerCase();
      if (!seenUrls.has(normalizedUrl)) {
        seenUrls.add(normalizedUrl);
        allMatches.push({ provider: provider.name, url });
      }
    });
  });

  if (allMatches.length > 0) {
    try {
      chrome.runtime.sendMessage({
        type: 'CLOUD_URLS_FOUND',
        urls: allMatches,
        pageUrl: window.location.href
      });
    } catch {
      // Extension context invalidated (e.g. after reload) — ignore
    }
  }
}

let lastScannedContent = '';

function findCloudUrls() {
  const pageContent = document.documentElement.innerHTML;
  if (pageContent === lastScannedContent) return;
  lastScannedContent = pageContent;
  scanContent(pageContent);
}

// Tracks already-fetched external resource URLs to avoid re-fetching within the same page load
const fetchedResources = new Set();

async function scanExternalResources() {
  const links = [
    ...[...document.querySelectorAll('link[rel="stylesheet"][href]')].map(el => el.href),
    ...[...document.querySelectorAll('script[src]')].map(el => el.src),
  ].filter(url => url.startsWith('http') && !fetchedResources.has(url));

  const MAX_BYTES = 2 * 1024 * 1024; // 2 MB per file

  for (const url of links) {
    fetchedResources.add(url);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 8000);
    try {
      const res = await fetch(url, { cache: 'force-cache', signal: controller.signal });
      clearTimeout(timer);
      const length = parseInt(res.headers.get('content-length') || '0', 10);
      if (length > MAX_BYTES) continue;
      const text = await res.text();
      if (text.length > MAX_BYTES) continue;
      scanContent(text);
    } catch {
      clearTimeout(timer);
      // Skip — timeout, cross-origin blocked, or network error
    }
  }
}

// Collects external hostnames from the page and sends them to background for CNAME lookup.
// Capped at 50 per page to avoid excessive DNS requests.
function collectExternalHostnames() {
  const hostnames = new Set();
  const pageHost  = window.location.hostname;

  [
    ...document.querySelectorAll('a[href]'),
    ...document.querySelectorAll('link[href]'),
    ...document.querySelectorAll('script[src]'),
    ...document.querySelectorAll('img[src]'),
  ].forEach(el => {
    const url = el.href || el.src;
    if (!url || !url.startsWith('http')) return;
    try {
      const h = new URL(url).hostname.toLowerCase();
      if (h !== pageHost && !h.endsWith('.' + pageHost)) hostnames.add(h);
    } catch {}
  });

  const limited = [...hostnames].slice(0, 50);
  if (limited.length === 0) return;
  try {
    chrome.runtime.sendMessage({ type: 'CHECK_CNAME', hostnames: limited, pageUrl: window.location.href });
  } catch {}
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => {
    findCloudUrls();
    scanExternalResources();
    collectExternalHostnames();
  });
} else {
  findCloudUrls();
  scanExternalResources();
  collectExternalHostnames();
}

const observer = new MutationObserver((mutations) => {
  const addedContent = mutations.reduce((acc, m) => {
    for (const node of m.addedNodes) {
      if (node.nodeType === Node.ELEMENT_NODE) acc += node.outerHTML + '\n';
    }
    return acc;
  }, '');

  if (addedContent) {
    scanContent(addedContent);
  }
});

observer.observe(document.documentElement, {
  childList: true,
  subtree: true,
  characterData: false
});

chrome.runtime.onMessage.addListener((request, _sender, sendResponse) => {
  if (request.action === 'scan') {
    findCloudUrls();
    sendResponse({ status: 'scan complete' });
  }
  return true;
});
