/**
 * download-skin-images.js
 * 
 * Stáhne všechny obrázky skinů ze Steam CDN přes ByMykel/CSGO-API databázi.
 * Zdroj obrázků: community.akamai.steamstatic.com (Steam CDN) - bez blokování!
 * 
 * Spustit: node download-skin-images.js
 * 
 * Po spuštění serveru se obrázky budou servírovat přímo z /assets/skins-cache/
 * bez potřeby externího CDN nebo proxy.
 */

const fs = require('fs/promises');
const path = require('path');
const crypto = require('crypto');

const OUT_DIR = path.join(__dirname, 'assets', 'skins-cache');
const INDEX_PATH = path.join(__dirname, 'index.html');
const CONCURRENCY = 10;
const TIMEOUT_MS = 15000;

// ByMykel CS2 API - free, open source, Steam CDN URLs
const BYMYKEL_API = 'https://raw.githubusercontent.com/ByMykel/CSGO-API/main/public/api/en/skins.json';

// Steam CDN headers
const HEADERS = {
  'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
  'Accept': 'image/avif,image/webp,image/apng,image/*,*/*;q=0.8',
};

function normalize(str) {
  return (str || '').toLowerCase().replace(/[★\s]+/g, ' ').replace(/[^a-z0-9 |]/g, '').trim();
}

async function fetchJSON(url) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 30000);
  try {
    const r = await fetch(url, { signal: controller.signal, headers: { 'User-Agent': 'Mozilla/5.0' } });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return await r.json();
  } finally {
    clearTimeout(timeout);
  }
}

async function downloadImage(url, stats) {
  const hash = crypto.createHash('sha1').update(url).digest('hex');
  const extFromUrl = path.extname(new URL(url).pathname).replace(/[^a-zA-Z0-9.]/g, '').slice(0, 6) || '.png';
  // Steam CDN images don't have extension in path, default to .png
  const ext = extFromUrl === '.' || !extFromUrl ? '.png' : extFromUrl;
  const filePath = path.join(OUT_DIR, `${hash}${ext}`);

  try {
    const stat = await fs.stat(filePath);
    if (stat.size > 500) { // at least 500 bytes = real image
      stats.skipped++;
      return { ok: true, skipped: true, filePath };
    }
  } catch {}

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), TIMEOUT_MS);

  try {
    const res = await fetch(url, { signal: controller.signal, headers: HEADERS });
    clearTimeout(timeout);
    if (!res.ok) { stats.failed++; return { ok: false, status: res.status }; }
    const ct = res.headers.get('content-type') || '';
    if (!ct.startsWith('image/')) { stats.failed++; return { ok: false, reason: 'non-image' }; }
    const buf = Buffer.from(await res.arrayBuffer());
    if (buf.length < 500) { stats.failed++; return { ok: false, reason: 'too small' }; }
    await fs.writeFile(filePath, buf);
    stats.downloaded++;
    return { ok: true, filePath };
  } catch (e) {
    clearTimeout(timeout);
    stats.failed++;
    return { ok: false, reason: e.message };
  }
}

async function processQueue(items, stats) {
  let idx = 0;
  const total = items.length;

  async function worker() {
    while (idx < total) {
      const i = idx++;
      const item = items[i];
      await downloadImage(item.url, stats);
      const done = stats.downloaded + stats.skipped + stats.failed;
      process.stdout.write(
        `\r[${String(done).padStart(4)}/${total}] ✓ ${stats.downloaded} staženo | ⏩ ${stats.skipped} cached | ✗ ${stats.failed} chyba  `
      );
    }
  }

  await Promise.all(Array.from({ length: CONCURRENCY }, () => worker()));
}

async function main() {
  console.log('🚀 OTODROP Skin Image Downloader');
  console.log('   Zdroj: ByMykel/CSGO-API → Steam CDN');
  console.log('==================================================');

  await fs.mkdir(OUT_DIR, { recursive: true });

  // 1. Stáhni databázi skinů z GitHubu
  console.log('\n📥 Stahuji databázi skinů z ByMykel/CSGO-API...');
  let skins;
  try {
    skins = await fetchJSON(BYMYKEL_API);
    console.log(`   ✅ Nalezeno ${skins.length} skinů v databázi`);
  } catch (e) {
    console.error('   ❌ Nepodařilo se stáhnout databázi:', e.message);
    process.exit(1);
  }

  // 2. Přečti rawSkinData z index.html - zjisti která jména potřebujeme
  console.log('\n📋 Čtu skiny z index.html...');
  const html = await fs.readFile(INDEX_PATH, 'utf8');
  const rawMatch = html.match(/const rawSkinData = `([\s\S]*?)`;/);
  const neededNames = new Set();
  
  if (rawMatch) {
    rawMatch[1].trim().split('\n').forEach(line => {
      const parts = line.split('|');
      if (parts.length < 4) return;
      const weapon = parts[0].trim();
      const finish = parts.slice(1, parts.length - 2).join('|').trim();
      neededNames.add(`${weapon} | ${finish}`);
      neededNames.add(`★ ${weapon} | ${finish}`); // knife prefix variant
    });
    console.log(`   ✅ Potřebujeme obrázky pro ${neededNames.size} skinů`);
  }

  // 3. Mapuj skiny z CSGO-API na naše skiny
  // Vytvoř mapu: normalizované jméno → Steam CDN URL
  const steamMap = new Map();
  for (const skin of skins) {
    if (skin.image) {
      const key = normalize(skin.name);
      steamMap.set(key, { url: skin.image, name: skin.name });
    }
  }

  // 4. Připrav seznam ke stažení
  const toDownload = [];
  const nameUrlMap = {}; // pro mapování v serveru

  // Projdi všechny skiny z API a stáhni jejich obrázky
  let matched = 0;
  for (const skin of skins) {
    if (!skin.image) continue;
    toDownload.push({ url: skin.image, name: skin.name });
    matched++;
  }

  // Přidej i Steam CDN URL z index.html (fallback, case images)
  const cdnUrlRegex = /https:\/\/community\.(?:akamai|cloudflare)\.steamstatic\.com\/economy\/image\/[^\s"'`<>)]+/g;
  const extraUrls = html.match(cdnUrlRegex) || [];
  for (const url of new Set(extraUrls)) {
    toDownload.push({ url, name: 'extra' });
  }

  console.log(`\n📊 Celkem ke stažení: ${toDownload.length} obrázků\n`);

  // 5. Ulož mapování pro server - aby věděl jaká URL patří k jakému souboru
  const mappingPath = path.join(OUT_DIR, '_name_to_hash.json');
  const mapping = {};
  for (const item of toDownload) {
    const hash = crypto.createHash('sha1').update(item.url).digest('hex');
    // Ext determination
    let ext;
    try {
      ext = path.extname(new URL(item.url).pathname).replace(/[^a-zA-Z0-9.]/g, '').slice(0, 6) || '.png';
    } catch { ext = '.png'; }
    if (!ext || ext === '.') ext = '.png';
    mapping[item.name] = { hash, ext, file: `${hash}${ext}`, url: item.url };
  }
  await fs.writeFile(mappingPath, JSON.stringify(mapping, null, 2));
  console.log(`💾 Mapa uložena: ${mappingPath}`);

  // 6. Stahuj!
  const stats = { downloaded: 0, skipped: 0, failed: 0 };
  const start = Date.now();
  await processQueue(toDownload, stats);

  // 7. Výsledek
  const elapsed = ((Date.now() - start) / 1000).toFixed(1);
  let totalSizeKB = 0;
  try {
    const files = await fs.readdir(OUT_DIR);
    const sizes = await Promise.all(files.filter(f => !f.startsWith('_')).map(f => 
      fs.stat(path.join(OUT_DIR, f)).then(s => s.size).catch(() => 0)
    ));
    totalSizeKB = Math.round(sizes.reduce((a, b) => a + b, 0) / 1024);
  } catch {}

  console.log('\n\n==================================================');
  console.log(`✅ Hotovo za ${elapsed}s`);
  console.log(`   📥 Nově staženo: ${stats.downloaded}`);
  console.log(`   ⏩ Již v cache: ${stats.skipped}`);
  console.log(`   ❌ Chyby: ${stats.failed}`);
  console.log(`   💾 Velikost cache: ${(totalSizeKB / 1024).toFixed(1)} MB`);
  console.log(`   📂 ${OUT_DIR}`);
  console.log('\n💡 TIP: Server nyní bude servírovat tyto obrázky přímo bez proxy!');
}

main().catch(e => {
  console.error('\n❌ Fatální chyba:', e.message);
  process.exit(1);
});
