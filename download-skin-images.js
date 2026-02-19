const fs = require('fs/promises');
const path = require('path');
const crypto = require('crypto');

function extractUrlsFromIndex(html) {
  // Bere VŠECHNY URL přímo z indexu (skins, speciální alts, case obrázky, atd.)
  const all = html.match(/https?:\/\/[^'"\s)<>`]+/g) || [];
  const cleaned = all
    .map((u) => u.replace(/[",'>)]*$/, '').trim())
    .filter((u) => /^https?:\/\//i.test(u));

  // Fallback whitelist styl odkazů, které se běžně v projektu používají
  const preferred = cleaned.filter((u) =>
    /steamstatic|casehug|cloudflare|cdn|steam|img|image|png|jpg|jpeg|webp|gif/i.test(u)
  );

  return Array.from(new Set(preferred.length ? preferred : cleaned));
}

async function main() {
  const indexPath = path.join(__dirname, 'index.html');
  const html = await fs.readFile(indexPath, 'utf8');
  const urls = extractUrlsFromIndex(html);

  const outDir = path.join(__dirname, 'assets', 'skins-cache');
  await fs.mkdir(outDir, { recursive: true });

  console.log(`Found ${urls.length} urls in index.html`);

  let i = 0;
  for (const rawUrl of urls) {
    i += 1;
    try {
      const url = rawUrl.trim();
      const pathname = new URL(url).pathname || '';
      const ext = (path.extname(pathname).slice(0, 5) || '.img').replace(/[^a-zA-Z0-9.]/g, '') || '.img';
      const file = path.join(outDir, `${crypto.createHash('sha1').update(url).digest('hex')}${ext}`);

      try {
        await fs.access(file);
        process.stdout.write(`\r[${i}/${urls.length}] cached`);
        continue;
      } catch {}

      const res = await fetch(url, { redirect: 'follow' });
      if (!res.ok) {
        process.stdout.write(`\r[${i}/${urls.length}] skip(${res.status})`);
        continue;
      }

      const arr = await res.arrayBuffer();
      await fs.writeFile(file, Buffer.from(arr));
      process.stdout.write(`\r[${i}/${urls.length}] downloaded`);
    } catch {
      process.stdout.write(`\r[${i}/${urls.length}] error`);
    }
  }

  console.log('\nDone');
  console.log(`Image cache folder: ${outDir}`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
