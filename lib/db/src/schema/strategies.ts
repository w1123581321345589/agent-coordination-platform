import { pgTable, text, serial, timestamp, integer, real } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod/v4";

export const strategiesTable = pgTable("strategies", {
  id: serial("id").primaryKey(),
  name: text("name").notNull(),
  description: text("description").notNull(),
  domain: text("domain").notNull(),
  coordinationPattern: text("coordination_pattern").notNull(),
  lifecycleStage: text("lifecycle_stage").notNull().default("ingest"),
  escalationRate: real("escalation_rate").notNull().default(0),
  evidenceCount: integer("evidence_count").notNull().default(0),
  expiresAt: timestamp("expires_at", { withTimezone: true }),
  previousStrategyId: integer("previous_strategy_id"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow().$onUpdate(() => new Date()),
});

export const insertStrategySchema = createInsertSchema(strategiesTable).omit({ id: true, createdAt: true, updatedAt: true });
export type InsertStrategy = z.infer<typeof insertStrategySchema>;
export type Strategy = typeof strategiesTable.$inferSelect;
