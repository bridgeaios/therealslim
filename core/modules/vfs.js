import fs from 'fs-extra';
import path from 'path';

const ROOT = "/systema";

export async function mountDrives({ drives, exclude }) {
  await fs.ensureDir(ROOT);

  const index = {};

  for (const drive of drives) {
    const basePath = `${drive}:/`;

    const files = await scan(basePath, exclude);
    index[drive] = files;
  }

  await deduplicate(index);

  return index;
}

async function scan(dir, exclude) {
  let results = [];

  try {
    const list = await fs.readdir(dir);

    for (const file of list) {
      if (exclude.some(e => file.includes(e))) continue;

      const full = path.join(dir, file);
      const stat = await fs.stat(full);

      if (stat.isDirectory()) {
        results = results.concat(await scan(full, exclude));
      } else {
        results.push(full);
      }
    }
  } catch (_err) {
    // Silently skip directories that are inaccessible (permission denied,
    // non-existent drive letters, etc.) — expected in a multi-drive scan.
  }

  return results;
}

async function deduplicate(index) {
  const seen = new Set();

  for (const drive in index) {
    index[drive] = index[drive].filter(file => {
    const basename = file.split('/').pop();
      if (seen.has(basename)) return false;
      seen.add(basename);
      return true;
    });
  }
}
