const fs = require('fs/promises');
const path = require('path');
const crypto = require('crypto');

async function main() {
  const html = await fs.readFile(path.join(__dirname, 'index.html'), 'utf8');
  const urls = Array.from(new Set((html.match(/https?:\/\/[^'"\s)]+\.(?:png|jpg|jpeg|webp|gif)(?:\?[^'"\s)]*)?/gi) || [])));
  const outDir = path.join(__dirname, 'assets', 'skins-cache');
  await fs.mkdir(outDir, { recursive: true });

  console.log(`Found ${urls.length} image URLs`);
  let i = 0;
  for (const url of urls) {
    i += 1;
    try {
      const ext = path.extname(new URL(url).pathname) || '.img';
      const file = path.join(outDir, `${crypto.createHash('sha1').update(url).digest('hex')}${ext.slice(0,5)}`);
      try { await fs.access(file); process.stdout.write(`\r[${i}/${urls.length}] cached`); continue; } catch {}
      const res = await fetch(url);
      if (!res.ok) { process.stdout.write(`\r[${i}/${urls.length}] skip`); continue; }
      const arr = await res.arrayBuffer();
      await fs.writeFile(file, Buffer.from(arr));
      process.stdout.write(`\r[${i}/${urls.length}] downloaded`);
    } catch {
      process.stdout.write(`\r[${i}/${urls.length}] error`);
    }
  }
  console.log('\nDone');
}

main().catch((e) => { console.error(e); process.exit(1); });
