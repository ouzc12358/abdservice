import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { chmod, writeFile } from "node:fs/promises";
import path from "node:path";

const destination = process.argv[2];
const keychainService = process.argv[3] || "abdservice-secure.cloudflare";

if (!destination || !path.isAbsolute(destination)) {
  throw new Error("Usage: node scripts/generate-deploy-secrets.mjs /absolute/path/to/secrets.env [keychain-service]");
}

const randomSecret = (bytes) => randomBytes(bytes).toString("base64url");
const secrets = {
  ADMIN: randomSecret(24),
  KEY: randomSecret(24),
  SESSION_SECRET: randomSecret(32),
  DATA_ENCRYPTION_KEY: randomSecret(32),
};

const dotenv = `${Object.entries(secrets).map(([name, value]) => `${name}=${value}`).join("\n")}\n`;
await writeFile(destination, dotenv, { encoding: "utf8", flag: "wx", mode: 0o600 });
await chmod(destination, 0o600);

if (process.platform === "darwin") {
  for (const account of ["ADMIN", "KEY"]) {
    execFileSync("/usr/bin/security", [
      "add-generic-password",
      "-U",
      "-s",
      keychainService,
      "-a",
      account,
      "-w",
      secrets[account],
    ], { stdio: "ignore" });
  }
}

console.log(JSON.stringify({
  secretsFile: destination,
  keychainService: process.platform === "darwin" ? keychainService : null,
}));
