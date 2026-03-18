const CHECK_CACHE_HOURS = 24;

// Write queue: each get/set must complete before the next one starts, preventing race conditions
let writeQueue = Promise.resolve();

// Must match the patterns in content.js
const CLOUD_PATTERNS = [
  { name: 'Azure Blob', pattern: /([a-z0-9-]+)\.blob\.core\.windows\.net(?:\/[^\s"'<>]*)?/i },
  { name: 'AWS S3', pattern: /([a-zA-Z0-9-.]+)\.s3(?:[.-]([a-z0-9-]+))?\.amazonaws\.com(?:\/[^\s"'<>]*)?/i },
  { name: 'Google Cloud Storage', pattern: /([a-zA-Z0-9._-]+)\.storage\.googleapis\.com(?:\/[^\s"'<>]*)?/i },
  { name: 'DigitalOcean Spaces', pattern: /([a-z0-9-]+)\.(?:[a-z0-9-]+\.)?digitaloceanspaces\.com(?:\/[^\s"'<>]*)?/i },
  { name: 'Cloudflare R2', pattern: /([a-z0-9-]+)\.r2\.(?:[a-z0-9-]+\.)?cloudflare\.com(?:\/[^\s"'<>]*)?/i },
];

function matchCloudUrl(url) {
  for (const { name, pattern } of CLOUD_PATTERNS) {
    if (pattern.test(url)) return name;
  }
  return null;
}

// ── Sensitive file detection ──────────────────────────────────────────────

// Suspicious stems per file extension. Empty array = any file with that extension is suspicious.
const EXTENSION_TYPE_MAP = {
  js: ['app', 'dev', 'config'],
  ts: ['app.module', 'environment', 'environment.prod'],
  json: [
    'config', 'default', 'settings', 'token', 'secret', 'secrets', 'client_secret',
    'deployment-config', 'appsettings', 'appsettings.production', 'appsettings.staging',
    'appsettings.development', 'swagger', 'remote-sync', '.remote-sync', 'sftp-config',
    'sftp', 'robomongo', 'logins', 'credentials', 'service_account',
    'application_default_credentials', 'serviceaccountkey', 'servicekey', 'gcloud',
    'prod', 'prod.secret',
  ],
  yaml: [
    'config', 'secrets', 'swagger', 'kubeconfig',
    'values', 'values.prod', 'values.staging', 'values.dev',
    'sealed-secrets', '.sops', 'travis', 'bitbucket-pipelines', 'application-auth',
  ],
  yml: [
    'config', 'secrets', 'swagger', 'kubeconfig',
    'values', 'values.prod', 'values.staging', 'values.dev',
    'sealed-secrets', '.sops', 'travis', 'bitbucket-pipelines', 'application-auth',
    'docker-compose', 'docker-compose.prod', 'docker-compose.override',
  ],
  toml: ['config', 'secrets', 'pyproject', 'cargo'],
  env: ['.env', 'local', 'production', 'staging', 'development', 'test', 'prod'],
  properties: ['config', 'application', 'configuration', 'db', 'database', 'mail', 'smtp'],
  ini: ['ventrilo_srv', 'config', 'database'],
  cfg: ['server', 'cccam', 'config'],
  conf: ['dhcpd', 'nginx', 'apache', 'httpd'],
  config: ['web'],
  tfstate: [],
  tfvars: ['terraform', 'prod', 'staging', 'secrets'],
  ps1: ['deploy', 'setup', 'appserverconfig', 'appserversetup'],
  sql: ['dump', 'backup', 'export', 'prod', 'db', 'database', 'users', 'accounts', 'customers'],
  dump: ['db', 'mysql', 'postgres', 'mongo', 'backup'],
  bak: ['db', 'database', 'backup'],
  mdf: [],
  sdf: [],
  pem: [],
  key: ['idea14', 'master', 'private', 'server', 'client'],
  private_key: ['otr'],
  p12: [],
  pfx: [],
  jks: [],
  keystore: [],
  ppk: [],
  kdbx: [],
  psafe3: [],
  ovpn: [],
  php: ['wp-config', 'localsettings', 'config.inc', 'database', 'settings'],
  rb: ['secret_token', 'carrierwave', 'knife'],
  py: ['settings', 'main', 'config', 'local_settings', 'production_settings'],
  java: ['constants', 'logintest', 'databaseconfig'],
  xml: [
    'filezilla', 'recentservers', 'connections', 'dbeaver-data-sources', 'webservers',
    'jenkins.plugins.publish_over_ssh.bapsshpublisherplugin', 'manifest',
  ],
  xpl: ['configuration.user'],
  plist: ['favorites'],
  txt: ['journal', 'github-recovery-codes', 'gitlab-recovery-codes', 'discord_backup_codes', 'recovery-codes', 'backup-codes'],
  zip: ['backup', 'db', 'database', 'config', 'secrets', 'source', 'src', 'prod'],
  tar: ['backup', 'db', 'config', 'secrets'],
  gz: ['backup', 'dump', 'db'],
  tgz: ['backup', 'config'],
};

// Compound extensions — empty array means any file ending with this is suspicious
const MULTI_EXT_MAP = {
  'tfstate.backup': [],
};

// Exact filename/stem keywords — suspicious regardless of extension
const ONLY_INCLUDE_KEYWORDS = new Set([
  '_netrc', '.netrc', 'passwd', 'shadow', 'master.passwd',
  'bash_history', 'sh_history', 'zsh_history', 'bash_profile', 'bashrc', 'zshrc',
  'id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519', 'authorized_keys', 'known_hosts',
  'credentials', '.aws', 's3cfg', 'gcloud',
  'kubeconfig', '.kube', 'vault-token', '.vault-token',
  'terraform.tfstate', 'terraform.tfvars',
  'npmrc', '.npmrc', 'npmrc_auth', '.pypirc',
  'database', 'pgpass', '.pgpass', 'esmtprc',
  'dockercfg', '.dockercfg',
  'ftpconfig', '.ftpconfig',
  'kwallet', 'keychain', 'htpasswd', '.htpasswd', '.htaccess',
  'rdp', 'cscfg', 'env', 'ovpn', 'gnupg', '.gnupg', 'wp-config',
]);

// Path patterns — match anywhere in the bucket key
const SENSITIVE_PATH_PATTERNS = [
  '.git/config', '.git/commit_editmsg', '.env',
  '.aws/credentials', '.aws/config', '.ssh/', '.kube/config',
  'config/database', 'config/secrets', 'config/credentials',
  'backup/', 'dump/', 'sql/',
  'terraform.tfstate', '.docker/config.json', 'wp-config.php',
];

function isSensitiveFile(rawKey) {
  const lower = rawKey.toLowerCase();
  const filename = lower.split('/').pop();
  if (!filename) return false;

  // 1. Path pattern match
  for (const p of SENSITIVE_PATH_PATTERNS) {
    if (lower === p || lower.endsWith('/' + p) || lower.startsWith(p) || lower.includes('/' + p)) return true;
  }

  // 2. Exact keyword match (with or without leading dot)
  const bare = filename.replace(/^\./, '');
  for (const kw of ONLY_INCLUDE_KEYWORDS) {
    const kwl = kw.toLowerCase().replace(/^\./, '');
    if (bare === kwl || filename === kw.toLowerCase()) return true;
  }

  // 3. Compound extension match (e.g. terraform.tfstate.backup)
  for (const [multiExt, stems] of Object.entries(MULTI_EXT_MAP)) {
    if (filename.endsWith('.' + multiExt)) {
      if (stems.length === 0) return true;
      const stem = filename.slice(0, -(multiExt.length + 1));
      if (stems.some(s => stem === s)) return true;
    }
  }

  // 4. Standard extension match
  const dotIdx = filename.lastIndexOf('.');
  if (dotIdx === -1) return false;
  const ext = filename.slice(dotIdx + 1);
  const stem = filename.slice(0, dotIdx);

  if (ext in EXTENSION_TYPE_MAP) {
    const stems = EXTENSION_TYPE_MAP[ext];
    if (stems.length === 0) return true;
    return stems.some(s => stem === s.toLowerCase());
  }

  return false;
}

function parseSensitiveFiles(xmlText) {
  const sensitive = [];
  // S3 / GCS style listing: <Key>filename</Key>
  (xmlText.match(/<Key>([^<]+)<\/Key>/g) || []).forEach(m => {
    const key = m.replace(/<\/?Key>/g, '');
    if (isSensitiveFile(key)) sensitive.push(key);
  });
  // Azure Blob style listing: <Name>filename</Name>
  (xmlText.match(/<Name>([^<]+)<\/Name>/g) || []).forEach(m => {
    const name = m.replace(/<\/?Name>/g, '');
    if (isSensitiveFile(name)) sensitive.push(name);
  });
  return [...new Set(sensitive)];
}

// In-memory CNAME cache — resets when the service worker restarts
const cnameCache = new Map();

async function checkDnsCname(hostname) {
  if (cnameCache.has(hostname)) return cnameCache.get(hostname);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 5000);
  try {
    const res = await fetch(
      `https://dns.google/resolve?name=${encodeURIComponent(hostname)}&type=CNAME`,
      { headers: { Accept: 'application/dns-json' }, signal: controller.signal }
    );
    clearTimeout(timer);
    const data = await res.json();
    const answer = (data.Answer || []).find(r => r.type === 5); // 5 = CNAME record
    const cname = answer ? answer.data.replace(/\.$/, '').toLowerCase() : null;
    cnameCache.set(hostname, cname);
    return cname;
  } catch {
    clearTimeout(timer);
    cnameCache.set(hostname, null);
    return null;
  }
}

function extractBucketHost(url) {
  const withProto = url.startsWith('http') ? url : 'https://' + url;
  try {
    return new URL(withProto).hostname.toLowerCase();
  } catch {
    return url.split('/')[0].toLowerCase();
  }
}

function extractAzureContainer(url) {
  const withProto = url.startsWith('http') ? url : 'https://' + url;
  try {
    const segments = new URL(withProto).pathname.split('/').filter(Boolean);
    return segments[0] || null;
  } catch {
    return null;
  }
}

function updateBucketIndex(index, urls, pageUrl) {
  const updated = { ...index };
  const now = new Date().toISOString();

  urls.forEach(({ provider, url }) => {
    const host = extractBucketHost(url);
    if (!updated[host]) {
      updated[host] = { provider, sites: [], firstSeen: now, lastSeen: now };
      // Store the first container seen for Azure — needed for misconfiguration checks
      if (provider === 'Azure Blob') {
        const container = extractAzureContainer(url);
        if (container) updated[host].container = container;
      }
    }
    if (!updated[host].sites.includes(pageUrl) && updated[host].sites.length < 500) {
      updated[host].sites.push(pageUrl);
    }
    updated[host].lastSeen = now;
  });

  return updated;
}

// Checks public listing status, subdomain takeover risk, and sensitive files.
// Write access is intentionally not checked — attempting a PUT without authorization
// could constitute unauthorized access under computer fraud laws.
async function checkBucketListing(host, provider, container) {
  const empty = { publicListing: null, takeoverRisk: false, sensitiveFiles: [] };
  let endpoint;

  if (provider === 'Azure Blob') {
    // Account-level listing always requires auth — must check at container level
    if (!container) return empty;
    endpoint = `https://${host}/${container}?restype=container&comp=list`;
  } else if (provider === 'AWS S3') {
    // Bucket names containing dots cause SSL wildcard cert failures on virtual-hosted URLs
    // (*.s3.amazonaws.com does not cover 808.ninja.s3.amazonaws.com).
    // For dotted names, fall back to path-style: https://s3[.region].amazonaws.com/bucket/
    const s3Match = host.match(/^(.+?)\.s3(?:[.-]([a-z0-9-]+))?\.amazonaws\.com$/);
    if (!s3Match) return empty;
    const bucketName = s3Match[1];
    const region = s3Match[2] || null;
    endpoint = bucketName.includes('.')
      ? `https://s3${region ? '.' + region : ''}.amazonaws.com/${bucketName}/`
      : `https://${host}/`;
  } else {
    const endpointMap = {
      'Google Cloud Storage': `https://${host}/`,
      'DigitalOcean Spaces': `https://${host}/`,
      // Cloudflare R2 does not expose a standard public listing endpoint
    };
    endpoint = endpointMap[provider];
  }

  if (!endpoint) return empty;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 10000);
  const MAX_RESPONSE_BYTES = 5 * 1024 * 1024; // 5 MB

  try {
    const res = await fetch(endpoint, { method: 'GET', redirect: 'follow', signal: controller.signal });
    clearTimeout(timer);

    if (res.status === 200) {
      const length = parseInt(res.headers.get('content-length') || '0', 10);
      if (length > MAX_RESPONSE_BYTES) return empty;
      const text = await res.text();
      if (text.length > MAX_RESPONSE_BYTES) return empty;
      return { publicListing: true, takeoverRisk: false, sensitiveFiles: parseSensitiveFiles(text) };
    }

    if (res.status === 404) {
      const len404 = parseInt(res.headers.get('content-length') || '0', 10);
      if (len404 > MAX_RESPONSE_BYTES) return empty;
      const text = await res.text();
      // NoSuchBucket on a DNS-resolvable host means the bucket was deleted but the record remains
      const takeoverRisk = text.includes('NoSuchBucket') || text.includes('BucketNotFound');
      return { publicListing: null, takeoverRisk, sensitiveFiles: [] };
    }

    if (res.status === 403 || res.status === 401) {
      return { publicListing: false, takeoverRisk: false, sensitiveFiles: [] };
    }

    return empty;
  } catch {
    clearTimeout(timer);
    return empty;
  }
}

function saveUrls(urls, pageUrl) {
  writeQueue = writeQueue.then(() => new Promise(resolve => {
    chrome.storage.local.get(['urlData', 'bucketIndex'], (result) => {
      const existingData = result.urlData || {};
      const existingIndex = result.bucketIndex || {};

      const existingUrls = existingData[pageUrl]?.urls || [];
      const seenKeys = new Set(existingUrls.map(u => `${u.provider}-${u.url.toLowerCase()}`));
      const mergedUrls = [...existingUrls];
      urls.forEach(u => {
        const key = `${u.provider}-${u.url.toLowerCase()}`;
        if (!seenKeys.has(key)) {
          seenKeys.add(key);
          mergedUrls.push(u);
        }
      });

      existingData[pageUrl] = {
        urls: mergedUrls,
        lastVisited: new Date().toISOString()
      };

      const updatedIndex = updateBucketIndex(existingIndex, urls, pageUrl);
      chrome.storage.local.set({ urlData: existingData, bucketIndex: updatedIndex }, resolve);
    });
  }));
}

// Intercept actual network requests to cloud storage — catches dynamically generated URLs
// that never appear in the page source (fetch/XHR calls, lazy-loaded resources, etc.)
chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    // Skip requests originating from this extension (e.g. bucket listing checks)
    if (!details.initiator || details.initiator.startsWith('chrome-extension://')) return;
    if (details.tabId === -1) return;

    const provider = matchCloudUrl(details.url);
    if (!provider) return;

    let cloudUrl;
    try {
      const parsed = new URL(details.url);
      cloudUrl = parsed.hostname + parsed.pathname;
    } catch {
      return;
    }

    const pageUrl = details.documentUrl || details.initiator;
    if (!pageUrl) return;
    saveUrls([{ provider, url: cloudUrl }], pageUrl);
  },
  {
    urls: [
      '*://*.blob.core.windows.net/*',
      '*://*.amazonaws.com/*',
      '*://*.storage.googleapis.com/*',
      '*://*.digitaloceanspaces.com/*',
      '*://*.cloudflare.com/*',
    ]
  }
);

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message.type === 'CLOUD_URLS_FOUND') {
    const { urls, pageUrl } = message;
    saveUrls(urls, pageUrl);
  }

  if (message.type === 'CHECK_BUCKETS') {
    chrome.storage.local.get(['bucketIndex', 'bucketStatus'], async (result) => {
      const bucketIndex = result.bucketIndex || {};
      const bucketStatus = result.bucketStatus || {};
      const staleThreshold = CHECK_CACHE_HOURS * 60 * 60 * 1000;
      const now = Date.now();

      const toCheck = Object.entries(bucketIndex).filter(([host]) => {
        const status = bucketStatus[host];
        if (!status) return true;
        return now - new Date(status.checkedAt).getTime() > staleThreshold;
      });

      for (const [host, { provider, container }] of toCheck) {
        const { publicListing, takeoverRisk, sensitiveFiles } = await checkBucketListing(host, provider, container);
        const prev = bucketStatus[host] || {};

        bucketStatus[host] = {
          publicListing,
          takeoverRisk,
          sensitiveFiles,
          checkedAt: new Date().toISOString(),
          // Keep the last 10 check results for the timeline view
          history: [
            ...(prev.history || []),
            { checkedAt: new Date().toISOString(), publicListing, takeoverRisk }
          ].slice(-10),
        };

        // Notify popup of each result as it arrives; suppress error if popup is closed
        chrome.runtime.sendMessage(
          { type: 'BUCKET_STATUS_UPDATE', host, publicListing, takeoverRisk, sensitiveFiles },
          () => void chrome.runtime.lastError
        );
      }

      // S3 dotted-bucket names cannot use virtual-hosted style (TLS wildcard limitation).
      // Path-style requests to the global endpoint get redirected back to virtual-hosted,
      // causing TLS failures. If a regional sibling of the same bucket was successfully
      // checked, copy its status to the non-regional hostname.
      const s3DottedGroups = {}; // bucketName -> [host, ...]
      for (const [h, info] of Object.entries(bucketIndex)) {
        if (info.provider !== 'AWS S3') continue;
        const m = h.match(/^(.+?)\.s3(?:[.-]([a-z0-9-]+))?\.amazonaws\.com$/);
        if (!m || !m[1].includes('.')) continue; // only dotted bucket names are affected
        if (!s3DottedGroups[m[1]]) s3DottedGroups[m[1]] = [];
        s3DottedGroups[m[1]].push(h);
      }
      for (const hosts of Object.values(s3DottedGroups)) {
        if (hosts.length < 2) continue;
        // Find the first host that has a definitive status (not unknown/null)
        const donor = hosts.find(h => bucketStatus[h] &&
          (bucketStatus[h].publicListing != null || bucketStatus[h].takeoverRisk));
        if (!donor) continue;
        const donorStatus = bucketStatus[donor];
        for (const h of hosts) {
          if (h === donor) continue;
          if (bucketStatus[h]?.publicListing != null || bucketStatus[h]?.takeoverRisk) continue;
          bucketStatus[h] = { ...donorStatus, checkedAt: new Date().toISOString() };
          chrome.runtime.sendMessage(
            {
              type: 'BUCKET_STATUS_UPDATE',
              host: h,
              publicListing: donorStatus.publicListing,
              takeoverRisk: donorStatus.takeoverRisk,
              sensitiveFiles: donorStatus.sensitiveFiles,
            },
            () => void chrome.runtime.lastError
          );
        }
      }

      chrome.storage.local.set({ bucketStatus });
      sendResponse({ done: true });
    });
    return true; // keep message channel open for async response
  }

  if (message.type === 'CHECK_CNAME') {
    const { hostnames, pageUrl } = message;
    (async () => {
      for (const hostname of hostnames) {
        const cname = await checkDnsCname(hostname);
        if (!cname) continue;
        const provider = matchCloudUrl(cname);
        if (!provider) continue;

        // Save the CNAME-discovered cloud host as a regular bucket
        const cloudHost = extractBucketHost(cname);
        saveUrls([{ provider, url: cloudHost }], pageUrl);

        // Record which custom domains (CNAMEs) point to this bucket
        writeQueue = writeQueue.then(() => new Promise(resolve => {
          chrome.storage.local.get(['bucketIndex'], (result) => {
            const idx = result.bucketIndex || {};
            if (idx[cloudHost]) {
              if (!idx[cloudHost].cnames) idx[cloudHost].cnames = [];
              if (!idx[cloudHost].cnames.includes(hostname) && idx[cloudHost].cnames.length < 100) {
                idx[cloudHost].cnames.push(hostname);
              }
            }
            chrome.storage.local.set({ bucketIndex: idx }, resolve);
          });
        }));
      }
    })();
  }
});
