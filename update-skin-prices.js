/**
 * update-skin-prices.js
 * 
 * Stáhne aktuální ceny skinů ze Steam Market a aktualizuje rawSkinData v index.html.
 * Ukládá průběh do prices-cache.json → můžeš přerušit (Ctrl+C) a znovu spustit.
 * 
 * Spustit: node update-skin-prices.js
 * 
 * Se Steam rate limitem to trvá cca 60-90 minut. Ale stačí spustit jednou.
 */

const fs = require('fs/promises');
const fsSync = require('fs');
const path = require('path');

const INDEX_PATH = path.join(__dirname, 'index.html');
const CACHE_PATH = path.join(__dirname, 'prices-cache.json');
const DELAY_MS = 3500;   // ms between requests (Steam rate limit ~20/min)
const CURRENCY = 3;      // 3 = EUR
const RETRY_DELAY = 35000; // 35s wait on rate limit

// Parse "41,86€" → 41.86
function parsePrice(str) {
  if (!str) return null;
  const cleaned = str.replace(/[^0-9,.\-]/g, '').replace(',', '.');
  const num = parseFloat(cleaned);
  return isNaN(num) ? null : Math.round(num * 100) / 100;
}

async function fetchPrice(marketHashName) {
  const url = `https://steamcommunity.com/market/priceoverview/?appid=730&currency=${CURRENCY}&market_hash_name=${encodeURIComponent(marketHashName)}`;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10000);
  try {
    const r = await fetch(url, {
      signal: controller.signal,
      headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' }
    });
    clearTimeout(timeout);
    if (r.status === 429) return { rateLimit: true };
    if (!r.ok) return { error: r.status };
    const json = await r.json();
    if (!json.success) return { noData: true };
    const lowest = parsePrice(json.lowest_price);
    const median = parsePrice(json.median_price);
    return { price: median || lowest || null, lowest, median };
  } catch (e) {
    clearTimeout(timeout);
    return { error: e.message };
  }
}

const KNIFE_TYPES = [
  "Bayonet","Bowie Knife","Butterfly Knife","Classic Knife","Falchion Knife","Flip Knife","Gut Knife",
  "Huntsman Knife","Karambit","M9 Bayonet","Navaja Knife","Nomad Knife","Paracord Knife","Shadow Daggers",
  "Skeleton Knife","Stiletto Knife","Survival Knife","Talon Knife","Ursus Knife","Kukri Knife"
];
const GLOVE_TYPES = ["Hand Wraps","Moto Gloves","Specialist Gloves","Sport Gloves","Bloodhound Gloves",
  "Driver Gloves","Hydra Gloves","Broken Fang Gloves"];

// Try different wears - Field-Tested first (most common/liquid)
const WEARS = ['(Field-Tested)', '(Minimal Wear)', '(Factory New)', '(Well-Worn)', '(Battle-Scarred)'];

function buildMarketName(weapon, skinName, wear) {
  const isKnife = KNIFE_TYPES.includes(weapon);
  const isGlove = GLOVE_TYPES.includes(weapon);
  const prefix = (isKnife || isGlove) ? '★ ' : '';
  return `${prefix}${weapon} | ${skinName} ${wear}`;
}

async function main() {
  console.log('🚀 OTODROP Steam Market Price Updater');
  console.log('=====================================');
  console.log('   Zdroj: Steam Community Market');
  console.log('   Měna: EUR (currency=3)');
  console.log('   Rate limit: ~20 req/min\n');

  const html = await fs.readFile(INDEX_PATH, 'utf8');
  const rawMatch = html.match(/const rawSkinData = `([\s\S]*?)`;/);
  if (!rawMatch) { console.error('❌ rawSkinData nenalezeno!'); process.exit(1); }

  const lines = rawMatch[1].trim().split('\n').map(l => l.trim()).filter(Boolean);
  console.log(`📋 ${lines.length} skinů v rawSkinData\n`);

  // Load cache
  let cache = {};
  try {
    cache = JSON.parse(await fs.readFile(CACHE_PATH, 'utf8'));
    const cachedCount = Object.values(cache).filter(c => c.price !== null).length;
    console.log(`💾 Cache: ${cachedCount} cen načteno\n`);
  } catch {
    console.log('📝 Žádná cache, stahuji od začátku\n');
  }

  let updated = 0, cached = 0, failed = 0, rateLimits = 0;
  const results = [];

  for (let i = 0; i < lines.length; i++) {
    const parts = lines[i].split('|');
    if (parts.length < 4) { results.push(lines[i]); continue; }

    const weapon = parts[0].trim();
    const skinName = parts.slice(1, parts.length - 2).join('|').trim();
    const oldPrice = parseFloat(parts[parts.length - 2].trim());
    const color = parts[parts.length - 1].trim();
    const key = `${weapon}|${skinName}`;

    // Use cache if fresh enough (< 7 days)
    if (cache[key] && cache[key].price !== undefined) {
      const age = Date.now() - new Date(cache[key].ts || 0).getTime();
      if (age < 7 * 24 * 3600 * 1000) {
        const p = cache[key].price || oldPrice;
        results.push(`${weapon}|${skinName}|${p.toFixed(2)}|${color}`);
        cached++;
        process.stdout.write(`\r[${i+1}/${lines.length}] ✓ ${updated} new | 💾 ${cached} cached | ✗ ${failed} kept   `);
        continue;
      }
    }

    // Fetch from Steam - try Field-Tested first, then other wears
    let foundPrice = null;
    for (const wear of WEARS) {
      const mName = buildMarketName(weapon, skinName, wear);
      await new Promise(r => setTimeout(r, DELAY_MS));

      const result = await fetchPrice(mName);

      if (result.rateLimit) {
        rateLimits++;
        process.stdout.write(`\n⚠️  Rate limit! Čekám ${RETRY_DELAY/1000}s...`);
        await new Promise(r => setTimeout(r, RETRY_DELAY));
        const retry = await fetchPrice(mName);
        if (retry.price) { foundPrice = retry.price; break; }
      } else if (result.price) {
        foundPrice = result.price;
        break;
      } else if (result.noData) {
        // This wear has no listings, try next
        continue;
      }
      // Only try first wear to save time, unless it had no data
      if (!result.noData) break;
    }

    if (foundPrice !== null && foundPrice > 0) {
      cache[key] = { price: foundPrice, ts: new Date().toISOString() };
      results.push(`${weapon}|${skinName}|${foundPrice.toFixed(2)}|${color}`);
      updated++;
    } else {
      // Keep old price
      cache[key] = { price: oldPrice, ts: new Date().toISOString(), kept: true };
      results.push(lines[i]);
      failed++;
    }

    process.stdout.write(`\r[${i+1}/${lines.length}] ✓ ${updated} new | 💾 ${cached} cached | ✗ ${failed} kept   `);

    // Save cache periodically
    if ((i + 1) % 15 === 0) {
      await fs.writeFile(CACHE_PATH, JSON.stringify(cache, null, 2));
    }
  }

  // Final save
  await fs.writeFile(CACHE_PATH, JSON.stringify(cache, null, 2));

  // Update index.html
  const newRawSkinData = results.join('\n');
  const newHtml = html.replace(rawMatch[1], newRawSkinData);
  await fs.writeFile(INDEX_PATH, newHtml, 'utf8');

  console.log('\n\n=====================================');
  console.log(`✅ Hotovo!`);
  console.log(`   📊 Nově staženo: ${updated}`);
  console.log(`   💾 Z cache: ${cached}`);
  console.log(`   ⏩ Ponechány staré ceny: ${failed}`);
  console.log(`   ⚠️  Rate limity: ${rateLimits}`);
  console.log(`\n💡 Spusť znovu pokud zbyly staré ceny (cache zrychlí).`);
}

main().catch(e => {
  console.error('\n❌ Chyba:', e.message);
  process.exit(1);
});
