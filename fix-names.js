const fs = require('fs');
const path = require('path');

const SKIN_MAPPING_PATH = path.join(__dirname, 'assets', 'skins-cache', '_name_to_hash.json');

const data = JSON.parse(fs.readFileSync(SKIN_MAPPING_PATH, 'utf8'));

const prefixesToRemove = [
  'slick_gloves_glove_driver_',
  'specialist_gloves_glove_specialist_',
  'sporty_gloves_glove_sport_',
  'bloodhound_gloves_glove_bloodhound_',
  'hand_wraps_glove_handwrap_leathery_',
  'moto_gloves_glove_motorcycle_',
  'hydra_gloves_glove_hydra_',
  'weapon_ak47_ak47_',
  'weapon_awp_awp_',
  'weapon_m4a1_m4a1_',
  'weapon_m4a1_silencer_m4a1_silencer_',
  'weapon_deagle_deagle_',
  'weapon_glock_glock_',
  'weapon_usp_silencer_usp_silencer_',
  'weapon_bayonet_bayonet_',
  'weapon_knife_karambit_knife_karambit_',
  'weapon_knife_m9_bayonet_knife_m9_bayonet_',
  'weapon_knife_butterfly_knife_butterfly_',
  'weapon_knife_tactical_knife_tactical_',
  'weapon_knife_survival_bowie_knife_survival_bowie_',
  'weapon_knife_push_knife_push_',
  'weapon_knife_gut_knife_gut_',
  'weapon_knife_falchion_knife_falchion_'
];

let changed = 0;
const newData = {};

for (const [key, value] of Object.entries(data)) {
  if (value.url.includes('default_generated')) {
    const filename = value.url.split('/').pop();
    let skinName = filename.replace(/_((light|heavy|medium)_)?png\.png$/, '');
    
    // remove prefixes
    for (const prefix of prefixesToRemove) {
      if (skinName.startsWith(prefix)) {
        skinName = skinName.substring(prefix.length);
        break;
      }
    }

    // capitalize words
    const properName = skinName.split('_').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' ');
    
    // build new key
    const parts = key.split(' | ');
    if (parts.length === 2) {
      const newKey = `${parts[0]} | ${properName}`;
      newData[newKey] = value;
      changed++;
      console.log(`Renamed: "${key}" -> "${newKey}"`);
    } else {
      newData[key] = value;
    }
  } else {
    newData[key] = value;
  }
}

fs.writeFileSync(SKIN_MAPPING_PATH, JSON.stringify(newData, null, 2));
console.log(`Saved. Changed ${changed} skins.`);
