import { pgTable, text, serial, timestamp, integer, real } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod/v4";

export const routingMappingsTable = pgTable("routing_mappings", {
  id: serial("id").primaryKey(),
  role: text("role").notNull(),
  provider: text("provider").notNull(),
  model: text("model").notNull(),
  rationale: text("rationale").notNull(),
  active: integer("active").notNull().default(1),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

export const insertRoutingMappingSchema = createInsertSchema(routingMappingsTable).omit({ id: true, createdAt: true });
export type InsertRoutingMapping = z.infer<typeof insertRoutingMappingSchema>;
export type RoutingMapping = typeof routingMappingsTable.$inferSelect;

export const routingPerformanceTable = pgTable("routing_performance", {
  id: serial("id").primaryKey(),
  role: text("role").notNull(),
  provider: text("provider").notNull(),
  model: text("model").notNull(),
  taskType: text("task_type").notNull(),
  qualityScore: real("quality_score").notNull(),
  costScore: real("cost_score").notNull(),
  latencyMs: integer("latency_ms").notNull(),
  compositeScore: real("composite_score").notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

export const insertRoutingPerformanceSchema = createInsertSchema(routingPerformanceTable).omit({ id: true, createdAt: true });
export type InsertRoutingPerformance = z.infer<typeof insertRoutingPerformanceSchema>;
export type RoutingPerformance = typeof routingPerformanceTable.$inferSelect;
