// A minimal Cloudflare D1 stand-in over node:sqlite, enough for the Worker's queries.
import { DatabaseSync } from "node:sqlite";
import fs from "node:fs";

class Stmt {
  constructor(db, sql, args = []) { this.db = db; this.sql = sql; this.args = args; }
  bind(...args) { return new Stmt(this.db, this.sql, args); }
  async first() { const r = this.db.prepare(this.sql).get(...this.args); return r ? { ...r } : null; }
  async all() { return { results: this.db.prepare(this.sql).all(...this.args).map((r) => ({ ...r })) }; }
  async run() { const r = this.db.prepare(this.sql).run(...this.args); return { meta: { changes: r.changes } }; }
  runSync() { this.db.prepare(this.sql).run(...this.args); }
}

export function d1(schemaPath) {
  const db = new DatabaseSync(":memory:");
  db.exec(fs.readFileSync(schemaPath, "utf8"));
  return {
    raw: db,
    prepare: (sql) => new Stmt(db, sql),
    async batch(stmts) {
      db.exec("BEGIN");
      try { for (const s of stmts) s.runSync(); db.exec("COMMIT"); } catch (e) { db.exec("ROLLBACK"); throw e; }
      return [];
    },
  };
}
