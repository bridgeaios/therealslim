import { boot } from './modules/bootloader.js';
import { mountDrives } from './modules/vfs.js';
import { initAPI } from './modules/api.js';
import { initIPC } from './modules/enigma-ipc.js';

(async () => {
  const secrets = await initIPC();
  const vfs = await mountDrives({
    drives: ["C", "D", "E"],
    exclude: ["Windows", "Program Files", "Program Files (x86)"]
  });

  await boot({ vfs, secrets });
  await initAPI({ vfs, secrets });
})();
