// popup.js
document.addEventListener('DOMContentLoaded', function () {
  const urlList       = document.getElementById('urlList');
  const bucketList    = document.getElementById('bucketList');
  const bucketMeta    = document.getElementById('bucketMeta');
  const clearAllBtn   = document.getElementById('clearAll');
  const checkAllBtn   = document.getElementById('checkAll');
  const exportTxtBtn  = document.getElementById('exportTxt');
  const exportJsonBtn = document.getElementById('exportJson');
  const exportCsvBtn  = document.getElementById('exportCsv');

  // Tracks which items have already been rendered to avoid full re-renders
  const renderedSites   = new Map(); // pageUrl  → containerElement
  const renderedBuckets = new Map(); // host     → containerElement

  // --- Tab switching ---
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
      btn.classList.add('active');
      document.getElementById(btn.dataset.tab).classList.add('active');
      if (btn.dataset.tab === 'buckets') displayBuckets();
    });
  });

  function formatDate(dateString) {
    return new Date(dateString).toLocaleString();
  }

  function extractHost(url) {
    const withProto = url.startsWith('http') ? url : 'https://' + url;
    try { return new URL(withProto).hostname.toLowerCase(); }
    catch { return url.split('/')[0].toLowerCase(); }
  }

  function makeStatusBadge(host, bucketStatus) {
    const s = bucketStatus[host];
    const span = document.createElement('span');
    span.dataset.host = host;

    if (!s || s.publicListing === null) {
      span.className = 'status-badge status-unknown';
      span.textContent = '?';
    } else if (s.publicListing === true) {
      span.className = 'status-badge status-public';
      span.textContent = 'Public';
    } else {
      span.className = 'status-badge status-private';
      span.textContent = 'Private';
    }

    return span;
  }

  // Updates every badge in the DOM that matches the given host
  function applyStatusUpdate(host, publicListing, takeoverRisk, sensitiveFiles) {
    const cls  = publicListing === true  ? 'status-public'
               : publicListing === false ? 'status-private'
               : 'status-unknown';
    const text = publicListing === true  ? 'Public'
               : publicListing === false ? 'Private'
               : '?';

    document.querySelectorAll(`[data-host="${host}"]`).forEach(badge => {
      badge.className = `status-badge ${cls}`;
      badge.textContent = text;
    });

    // Update the detail sections inside the bucket container
    const container = renderedBuckets.get(host);
    if (!container) return;

    const header = container.querySelector('.bucket-header');

    // Takeover risk badge in header
    let takeoverHeaderBadge = container.querySelector('.header-takeover-badge');
    if (takeoverRisk) {
      if (!takeoverHeaderBadge) {
        takeoverHeaderBadge = document.createElement('span');
        takeoverHeaderBadge.className = 'status-badge status-takeover header-takeover-badge';
        takeoverHeaderBadge.textContent = 'Takeover Risk';
        header.appendChild(takeoverHeaderBadge);
      }
    } else if (takeoverHeaderBadge) {
      takeoverHeaderBadge.remove();
    }

    // Sensitive files badge in header
    let sensitiveHeaderBadge = container.querySelector('.header-sensitive-badge');
    if (sensitiveFiles && sensitiveFiles.length > 0) {
      if (!sensitiveHeaderBadge) {
        sensitiveHeaderBadge = document.createElement('span');
        sensitiveHeaderBadge.className = 'status-badge status-sensitive header-sensitive-badge';
        header.appendChild(sensitiveHeaderBadge);
      }
      sensitiveHeaderBadge.textContent = `${sensitiveFiles.length} sensitive`;
    } else if (sensitiveHeaderBadge) {
      sensitiveHeaderBadge.remove();
    }

    // Takeover risk section
    let takeoverEl = container.querySelector('.takeover-section');
    if (takeoverRisk) {
      if (!takeoverEl) {
        takeoverEl = document.createElement('div');
        takeoverEl.className = 'detail-section danger takeover-section';
        takeoverEl.innerHTML = '<strong>⚠ Subdomain Takeover Risk</strong>Bucket does not exist but DNS record is still active.';
        container.querySelector('.bucket-content').appendChild(takeoverEl);
      }
    } else if (takeoverEl) {
      takeoverEl.remove();
    }

    // Sensitive files section
    let sensitiveEl = container.querySelector('.sensitive-section');
    if (sensitiveFiles && sensitiveFiles.length > 0) {
      if (!sensitiveEl) {
        sensitiveEl = document.createElement('div');
        sensitiveEl.className = 'detail-section danger sensitive-section';
        container.querySelector('.bucket-content').appendChild(sensitiveEl);
      }
      sensitiveEl.innerHTML = '';
      const sh = document.createElement('strong');
      sh.textContent = `Sensitive Files (${sensitiveFiles.length})`;
      sensitiveEl.appendChild(sh);
      sensitiveFiles.forEach(f => {
        const d = document.createElement('div');
        d.className = 'file-item';
        d.textContent = f;
        sensitiveEl.appendChild(d);
      });
    } else if (sensitiveEl) {
      sensitiveEl.remove();
    }
  }

  // ── By Site tab ────────────────────────────────────────────────────────────

  function buildSiteContainer(hostname, data, bucketStatus) {
    const container = document.createElement('div');
    container.className = 'site-container';

    const header = document.createElement('div');
    header.className = 'site-header';
    const headerContent = document.createElement('div');
    headerContent.className = 'header-content';
    const arrow = document.createElement('span');
    arrow.className = 'arrow';
    arrow.innerHTML = '&rarr;';
    const label = document.createElement('strong');
    label.textContent = 'Domain: ';
    const hostnameSpan = document.createElement('span');
    hostnameSpan.textContent = hostname;
    headerContent.appendChild(arrow);
    headerContent.appendChild(label);
    headerContent.appendChild(hostnameSpan);
    header.appendChild(headerContent);
    header.addEventListener('click', () => {
      const content = container.querySelector('.site-content');
      arrow.classList.toggle('expanded');
      content.style.display = arrow.classList.contains('expanded') ? 'block' : 'none';
    });
    container.appendChild(header);

    const siteContent = document.createElement('div');
    siteContent.className = 'site-content';
    siteContent.style.display = 'none';

    const ts = document.createElement('div');
    ts.className = 'timestamp';
    ts.textContent = `Last visited: ${formatDate(data.lastVisited)}`;
    siteContent.appendChild(ts);

    const uniqueUrlMap = new Map();
    let counter = 1;
    data.urls.forEach(u => {
      const key = `${u.provider}-${u.url.toLowerCase()}`;
      if (!uniqueUrlMap.has(key)) uniqueUrlMap.set(key, { ...u, number: counter++ });
    });

    const byProvider = {};
    uniqueUrlMap.forEach(u => {
      if (!byProvider[u.provider]) byProvider[u.provider] = [];
      byProvider[u.provider].push(u);
    });

    Object.entries(byProvider).forEach(([provider, urls]) => {
      const section = document.createElement('div');
      section.className = 'provider-section';
      const name = document.createElement('div');
      name.className = 'provider-name';
      name.textContent = provider;
      section.appendChild(name);

      urls.forEach(u => {
        const row = document.createElement('div');
        row.className = 'url-item';

        const num = document.createElement('span');
        num.className = 'url-number';
        num.textContent = `${u.number}.`;

        const text = document.createElement('span');
        text.className = 'url-text';
        text.textContent = u.url;

        row.appendChild(num);
        row.appendChild(text);
        row.appendChild(makeStatusBadge(extractHost(u.url), bucketStatus));
        section.appendChild(row);
      });

      siteContent.appendChild(section);
    });

    container.appendChild(siteContent);
    return container;
  }

  // Groups urlData entries by hostname, merging URLs from different pages of the same site
  function groupByHostname(urlData) {
    const grouped = {};
    Object.entries(urlData).forEach(([pageUrl, data]) => {
      let hostname;
      try { hostname = new URL(pageUrl).hostname; }
      catch { hostname = pageUrl; }

      if (!grouped[hostname]) {
        grouped[hostname] = { urls: [], lastVisited: data.lastVisited };
      }

      data.urls.forEach(u => {
        const key = `${u.provider}-${u.url.toLowerCase()}`;
        if (!grouped[hostname].urls.some(e => `${e.provider}-${e.url.toLowerCase()}` === key)) {
          grouped[hostname].urls.push(u);
        }
      });

      if (data.lastVisited > grouped[hostname].lastVisited) {
        grouped[hostname].lastVisited = data.lastVisited;
      }
    });
    return grouped;
  }

  function displayUrls() {
    chrome.storage.local.get(['urlData', 'bucketStatus'], function (result) {
      const urlData      = result.urlData      || {};
      const bucketStatus = result.bucketStatus || {};
      const grouped      = groupByHostname(urlData);

      if (Object.keys(grouped).length === 0) {
        urlList.innerHTML = '<div class="url-item">No cloud storage URLs found.</div>';
        renderedSites.clear();
        return;
      }

      // Remove sites from DOM that no longer exist in storage
      renderedSites.forEach((el, hostname) => {
        if (!grouped[hostname]) { el.remove(); renderedSites.delete(hostname); }
      });

      // Clear the "no URLs found" message if it was previously shown
      const emptyMsg = urlList.querySelector('.url-item');
      if (emptyMsg && renderedSites.size === 0) urlList.innerHTML = '';

      Object.entries(grouped)
        .sort(([, a], [, b]) => new Date(b.lastVisited) - new Date(a.lastVisited))
        .forEach(([hostname, data]) => {
          if (renderedSites.has(hostname)) return; // already rendered, skip
          const el = buildSiteContainer(hostname, data, bucketStatus);
          renderedSites.set(hostname, el);
          urlList.appendChild(el);
        });
    });
  }

  // ── Buckets tab ────────────────────────────────────────────────────────────

  function buildBucketContainer(host, info, bucketStatus) {
    const container = document.createElement('div');
    container.className = 'bucket-container';

    const header = document.createElement('div');
    header.className = 'bucket-header';

    const arrow = document.createElement('span');
    arrow.className = 'arrow';
    arrow.innerHTML = '&rarr;';

    const nameSpan = document.createElement('span');
    nameSpan.className = 'bucket-name';
    nameSpan.textContent = host;

    const providerBadge = document.createElement('span');
    providerBadge.className = 'provider-badge';
    providerBadge.textContent = info.provider;

    header.appendChild(arrow);
    header.appendChild(nameSpan);
    header.appendChild(providerBadge);

    if (info.sites.length >= 2) {
      const crossBadge = document.createElement('span');
      crossBadge.className = 'cross-site-badge';
      crossBadge.textContent = `${info.sites.length} sites`;
      header.appendChild(crossBadge);
    }

    const status = bucketStatus[host] || {};

    // Status badge
    header.appendChild(makeStatusBadge(host, bucketStatus));

    // Takeover risk badge in header
    if (status.takeoverRisk) {
      const tb = document.createElement('span');
      tb.className = 'status-badge status-takeover';
      tb.textContent = 'Takeover Risk';
      header.appendChild(tb);
    }

    // Sensitive files badge in header
    if (status.sensitiveFiles && status.sensitiveFiles.length > 0) {
      const sb = document.createElement('span');
      sb.className = 'status-badge status-sensitive';
      sb.textContent = `${status.sensitiveFiles.length} sensitive`;
      header.appendChild(sb);
    }

    // CNAME badge in header
    if (info.cnames && info.cnames.length > 0) {
      const cb = document.createElement('span');
      cb.className = 'cname-badge';
      cb.textContent = `CNAME`;
      cb.title = info.cnames.join(', ');
      header.appendChild(cb);
    }

    header.addEventListener('click', () => {
      const content = container.querySelector('.bucket-content');
      arrow.classList.toggle('expanded');
      content.style.display = arrow.classList.contains('expanded') ? 'block' : 'none';
    });

    container.appendChild(header);

    const content = document.createElement('div');
    content.className = 'bucket-content';

    // Sites list
    const sitesLabel = document.createElement('div');
    sitesLabel.className = 'timestamp';
    sitesLabel.textContent = `Seen on ${info.sites.length} site${info.sites.length > 1 ? 's' : ''}:`;
    content.appendChild(sitesLabel);
    info.sites.forEach(site => {
      const div = document.createElement('div');
      div.className = 'bucket-site';
      div.textContent = site;
      content.appendChild(div);
    });

    // CNAME mappings section
    if (info.cnames && info.cnames.length > 0) {
      const cnameSection = document.createElement('div');
      cnameSection.className = 'detail-section info';
      const ch = document.createElement('strong');
      ch.textContent = 'Custom domains pointing here';
      cnameSection.appendChild(ch);
      info.cnames.forEach(c => {
        const d = document.createElement('div');
        d.className = 'cname-item';
        d.textContent = c;
        cnameSection.appendChild(d);
      });
      content.appendChild(cnameSection);
    }

    // Takeover risk section
    if (status.takeoverRisk) {
      const takeoverSection = document.createElement('div');
      takeoverSection.className = 'detail-section danger takeover-section';
      takeoverSection.innerHTML = '<strong>⚠ Subdomain Takeover Risk</strong>Bucket does not exist but DNS record is still active.';
      content.appendChild(takeoverSection);
    }

    // Sensitive files section
    if (status.sensitiveFiles && status.sensitiveFiles.length > 0) {
      const sensitiveSection = document.createElement('div');
      sensitiveSection.className = 'detail-section danger sensitive-section';
      const ssh = document.createElement('strong');
      ssh.textContent = `Sensitive Files (${status.sensitiveFiles.length})`;
      sensitiveSection.appendChild(ssh);
      status.sensitiveFiles.forEach(f => {
        const d = document.createElement('div');
        d.className = 'file-item';
        d.textContent = f;
        sensitiveSection.appendChild(d);
      });
      content.appendChild(sensitiveSection);
    }

    // Timeline section
    if (status.history && status.history.length > 0) {
      const tlSection = document.createElement('div');
      tlSection.className = 'detail-section info timeline';
      tlSection.innerHTML = '<strong>Check History</strong>';
      status.history.slice().reverse().forEach(h => {
        const item = document.createElement('div');
        item.className = 'timeline-item';

        const dotClass = h.takeoverRisk      ? 'takeover'
          : h.publicListing === true  ? 'public'
          : h.publicListing === false ? 'private'
          : 'unknown';
        const dotText = h.takeoverRisk      ? '⚠'
          : h.publicListing === true  ? '●'
          : h.publicListing === false ? '●'
          : '○';

        const dot = document.createElement('span');
        dot.className = `tl-dot ${dotClass}`;
        dot.textContent = dotText;

        const dateSpan = document.createElement('span');
        dateSpan.textContent = formatDate(h.checkedAt);

        item.appendChild(dot);
        item.appendChild(dateSpan);
        tlSection.appendChild(item);
      });
      content.appendChild(tlSection);
    }

    container.appendChild(content);
    return container;
  }

  function displayBuckets() {
    chrome.storage.local.get(['bucketIndex', 'bucketStatus'], function (result) {
      const bucketIndex  = result.bucketIndex  || {};
      const bucketStatus = result.bucketStatus || {};

      const total     = Object.keys(bucketIndex).length;
      const crossSite = Object.values(bucketIndex).filter(b => b.sites.length >= 2).length;
      bucketMeta.textContent = total
        ? `${total} bucket${total !== 1 ? 's' : ''} \u00B7 ${crossSite} cross-site`
        : '';

      if (total === 0) {
        bucketList.innerHTML = '<div class="url-item">No buckets found yet.</div>';
        renderedBuckets.clear();
        return;
      }

      // Remove buckets from DOM that no longer exist in storage
      renderedBuckets.forEach((el, host) => {
        if (!bucketIndex[host]) { el.remove(); renderedBuckets.delete(host); }
      });

      // Clear the "no buckets" message if it was previously shown
      const emptyMsg = bucketList.querySelector('.url-item');
      if (emptyMsg && renderedBuckets.size === 0) bucketList.innerHTML = '';

      // Sort: cross-site first, then by most recently seen
      Object.entries(bucketIndex)
        .sort(([, a], [, b]) => {
          if (b.sites.length !== a.sites.length) return b.sites.length - a.sites.length;
          return new Date(b.lastSeen) - new Date(a.lastSeen);
        })
        .forEach(([host, info]) => {
          if (renderedBuckets.has(host)) return; // already rendered, skip
          const el = buildBucketContainer(host, info, bucketStatus);
          renderedBuckets.set(host, el);
          bucketList.appendChild(el);
        });
    });
  }

  // ── Live updates from background ──────────────────────────────────────────

  chrome.runtime.onMessage.addListener((message) => {
    if (message.type === 'BUCKET_STATUS_UPDATE') {
      applyStatusUpdate(message.host, message.publicListing, message.takeoverRisk, message.sensitiveFiles);
    }
  });

  // ── Check All button ───────────────────────────────────────────────────────

  checkAllBtn.addEventListener('click', function () {
    checkAllBtn.disabled = true;
    checkAllBtn.textContent = 'Checking...';
    chrome.runtime.sendMessage({ type: 'CHECK_BUCKETS' }, () => {
      checkAllBtn.disabled = false;
      checkAllBtn.textContent = 'Check All';
    });
  });

  function triggerDownload(content, filename, mime) {
    const blob = new Blob([content], { type: mime });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href     = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  }

  function dateSlug() { return new Date().toISOString().slice(0, 10); }

  // ── Export TXT ────────────────────────────────────────────────────────────

  exportTxtBtn.addEventListener('click', function () {
    chrome.storage.local.get(['urlData', 'bucketIndex', 'bucketStatus'], function (result) {
      const urlData      = result.urlData      || {};
      const bucketIndex  = result.bucketIndex  || {};
      const bucketStatus = result.bucketStatus || {};
      const lines = [];

      lines.push('=== BY SITE ===');
      const grouped = groupByHostname(urlData);
      Object.entries(grouped)
        .sort(([, a], [, b]) => new Date(b.lastVisited) - new Date(a.lastVisited))
        .forEach(([hostname, data]) => {
          lines.push('');
          lines.push(`[${hostname}]`);
          lines.push(`Last visited: ${formatDate(data.lastVisited)}`);
          const byProvider = {};
          data.urls.forEach(u => {
            if (!byProvider[u.provider]) byProvider[u.provider] = [];
            byProvider[u.provider].push(u.url);
          });
          Object.entries(byProvider).forEach(([provider, urls]) => {
            lines.push(`  ${provider}:`);
            urls.forEach((url, i) => lines.push(`    ${i + 1}. ${url}`));
          });
        });

      lines.push('');
      lines.push('=== BUCKETS ===');
      Object.entries(bucketIndex)
        .sort(([, a], [, b]) => b.sites.length - a.sites.length)
        .forEach(([host, info]) => {
          const status = bucketStatus[host];
          const statusText = !status ? 'Unchecked'
            : status.publicListing === true  ? 'Public'
            : status.publicListing === false ? 'Private'
            : 'Unknown';
          lines.push('');
          lines.push(`${host}`);
          lines.push(`  Provider: ${info.provider}`);
          lines.push(`  Status: ${statusText}`);
          lines.push(`  Sites (${info.sites.length}):`);
          info.sites.forEach(s => lines.push(`    - ${s}`));
        });

      triggerDownload(lines.join('\n'), `skytage-${dateSlug()}.txt`, 'text/plain');
    });
  });

  // ── Export JSON ───────────────────────────────────────────────────────────

  exportJsonBtn.addEventListener('click', function () {
    chrome.storage.local.get(['urlData', 'bucketIndex', 'bucketStatus'], function (result) {
      const payload = {
        exportedAt: new Date().toISOString(),
        urlData:      result.urlData      || {},
        bucketIndex:  result.bucketIndex  || {},
        bucketStatus: result.bucketStatus || {},
      };
      triggerDownload(JSON.stringify(payload, null, 2), `skytage-${dateSlug()}.json`, 'application/json');
    });
  });

  // ── Export CSV ────────────────────────────────────────────────────────────

  exportCsvBtn.addEventListener('click', function () {
    chrome.storage.local.get(['bucketIndex', 'bucketStatus'], function (result) {
      const bucketIndex  = result.bucketIndex  || {};
      const bucketStatus = result.bucketStatus || {};

      const rows = [['host', 'provider', 'sites_count', 'public_listing', 'takeover_risk', 'sensitive_files', 'cnames', 'first_seen', 'last_seen']];

      Object.entries(bucketIndex).forEach(([host, info]) => {
        const s = bucketStatus[host] || {};
        rows.push([
          host,
          info.provider,
          info.sites.length,
          s.publicListing === true ? 'public' : s.publicListing === false ? 'private' : 'unknown',
          s.takeoverRisk ? 'yes' : 'no',
          (s.sensitiveFiles || []).join(' | '),
          (info.cnames || []).join(' | '),
          info.firstSeen,
          info.lastSeen,
        ]);
      });

      const csv = rows.map(r => r.map(v => `"${String(v ?? '').replace(/"/g, '""')}"`).join(',')).join('\n');
      triggerDownload(csv, `skytage-${dateSlug()}.csv`, 'text/csv');
    });
  });

  // ── Clear All ──────────────────────────────────────────────────────────────

  clearAllBtn.addEventListener('click', function () {
    if (confirm('Are you sure you want to clear all stored data?')) {
      chrome.storage.local.clear(function () {
        renderedSites.clear();
        renderedBuckets.clear();
        displayUrls();
        displayBuckets();
      });
    }
  });

  displayUrls();
});
