import { runMigrations } from "./index.js";

const databaseUrl = process.env["DATABASE_URL"];

if (!databaseUrl) {
  console.error("DATABASE_URL is required for migrations");
  process.exit(1);
}

await runMigrations(databaseUrl);
console.log("migrations applied");
