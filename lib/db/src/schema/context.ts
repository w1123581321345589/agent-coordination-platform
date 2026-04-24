import { pgTable, text, serial, timestamp, integer, real } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod/v4";

export const contextDomainsTable = pgTable("context_domains", {
  id: serial("id").primaryKey(),
  name: text("name").notNull().unique(),
  description: text("description").notNull(),
  disclosureTier: integer("disclosure_tier").notNull().default(1),
  dependencies: text("dependencies").array().notNull().default([]),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

export const insertContextDomainSchema = createInsertSchema(contextDomainsTable).omit({ id: true, createdAt: true });
export type InsertContextDomain = z.infer<typeof insertContextDomainSchema>;
export type ContextDomain = typeof contextDomainsTable.$inferSelect;

export const shapleyValuesTable = pgTable("shapley_values", {
  id: serial("id").primaryKey(),
  agentId: integer("agent_id").notNull(),
  taskType: text("task_type").notNull(),
  domain: text("domain").notNull(),
  shapleyValue: real("shapley_value").notNull(),
  samples: integer("samples").notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

export const insertShapleyValueSchema = createInsertSchema(shapleyValuesTable).omit({ id: true, createdAt: true });
export type InsertShapleyValue = z.infer<typeof insertShapleyValueSchema>;
export type ShapleyValue = typeof shapleyValuesTable.$inferSelect;
