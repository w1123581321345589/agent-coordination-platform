import { pgTable, text, serial, timestamp, integer } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod/v4";

export const threatRulesTable = pgTable("threat_rules", {
  id: serial("id").primaryKey(),
  ruleCode: text("rule_code").notNull().unique(),
  name: text("name").notNull(),
  description: text("description").notNull(),
  severity: text("severity").notNull().default("medium"),
  enabled: integer("enabled").notNull().default(1),
  firedCount: integer("fired_count").notNull().default(0),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

export const insertThreatRuleSchema = createInsertSchema(threatRulesTable).omit({ id: true, createdAt: true });
export type InsertThreatRule = z.infer<typeof insertThreatRuleSchema>;
export type ThreatRule = typeof threatRulesTable.$inferSelect;

export const threatEventsTable = pgTable("threat_events", {
  id: serial("id").primaryKey(),
  ruleId: integer("rule_id").notNull(),
  ruleCode: text("rule_code").notNull(),
  agentId: integer("agent_id"),
  sessionId: integer("session_id"),
  severity: text("severity").notNull(),
  details: text("details").notNull(),
  resolved: integer("resolved").notNull().default(0),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

export const insertThreatEventSchema = createInsertSchema(threatEventsTable).omit({ id: true, createdAt: true });
export type InsertThreatEvent = z.infer<typeof insertThreatEventSchema>;
export type ThreatEvent = typeof threatEventsTable.$inferSelect;
