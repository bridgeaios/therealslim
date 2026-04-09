export async function boot({ vfs, secrets }) {
  console.log("SYSTEMA BOOT INIT");

  if (!secrets.API_KEY) {
    throw new Error("Missing API_KEY from Enigma");
  }

  console.log("Drives mounted:", Object.keys(vfs));
  console.log("System ready");
}
