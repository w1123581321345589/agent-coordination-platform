import { pgTable, text, serial, timestamp, integer } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod/v4";

export const workItemsTable = pgTable("work_items", {
  id: serial("id").primaryKey(),
  taskDescription: text("task_description").notNull(),
  domain: text("domain").notNull(),
  priority: integer("priority").notNull().default(5),
  status: text("status").notNull().default("queued"),
  originalAgentId: integer("original_agent_id"),
  claimedByAgentId: integer("claimed_by_agent_id"),
  recoveryContext: text("recovery_context"),
  threatEventId: integer("threat_event_id"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow().$onUpdate(() => new Date()),
});

export const insertWorkItemSchema = createInsertSchema(workItemsTable).omit({ id: true, createdAt: true, updatedAt: true });
export type InsertWorkItem = z.infer<typeof insertWorkItemSchema>;
export type WorkItem = typeof workItemsTable.$inferSelect;

export const recoveryEventsTable = pgTable("recovery_events", {
  id: serial("id").primaryKey(),
  eventType: text("event_type").notNull(),
  workItemId: integer("work_item_id"),
  agentId: integer("agent_id"),
  payload: text("payload").notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

export const insertRecoveryEventSchema = createInsertSchema(recoveryEventsTable).omit({ id: true, createdAt: true });
export type InsertRecoveryEvent = z.infer<typeof insertRecoveryEventSchema>;
export type RecoveryEvent = typeof recoveryEventsTable.$inferSelect;
