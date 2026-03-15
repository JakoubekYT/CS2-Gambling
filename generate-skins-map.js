
const fs = require('fs/promises');
const path = require('path');

const OUT_DIR = path.join(__dirname, 'assets', 'skins-cache');
const SKIN_MAPPING_PATH = path.join(OUT_DIR, '_name_to_hash.json');
const BYMYKEL_API = 'https://raw.githubusercontent.com/ByMykel/CSGO-API/main/public/api/en/skins.json';

async function run() {
  console.log('Fetching skins database from ByMykel API...');
  await fs.mkdir(OUT_DIR, { recursive: true });

  const res = await fetch(BYMYKEL_API);
  if (!res.ok) throw new Error('API failed');
  const skins = await res.json();

  const mapping = {};
  skins.forEach(s => {
    if (s.name && s.image) {
      // Create object with url property for server.js compatibility
      mapping[s.name] = { url: s.image };
    }
  });

  await fs.writeFile(SKIN_MAPPING_PATH, JSON.stringify(mapping, null, 2));
  console.log(`✅ Success! Generated mapping for ${Object.keys(mapping).length} skins.`);
}

run();
