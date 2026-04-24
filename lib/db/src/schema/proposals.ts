import { pgTable, text, serial, timestamp, integer } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod/v4";

export const proposalsTable = pgTable("proposals", {
  id: serial("id").primaryKey(),
  title: text("title").notNull(),
  description: text("description").notNull(),
  triggerPatternId: integer("trigger_pattern_id"),
  proposedRole: text("proposed_role").notNull(),
  proposedCapabilities: text("proposed_capabilities").array().notNull().default([]),
  status: text("status").notNull().default("pending"),
  expiresAt: timestamp("expires_at", { withTimezone: true }),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow().$onUpdate(() => new Date()),
});

export const insertProposalSchema = createInsertSchema(proposalsTable).omit({ id: true, createdAt: true, updatedAt: true });
export type InsertProposal = z.infer<typeof insertProposalSchema>;
export type Proposal = typeof proposalsTable.$inferSelect;

export const failurePatternsTable = pgTable("failure_patterns", {
  id: serial("id").primaryKey(),
  taskType: text("task_type").notNull(),
  domain: text("domain").notNull(),
  failureCount: integer("failure_count").notNull().default(1),
  lastFailedAt: timestamp("last_failed_at", { withTimezone: true }).notNull().defaultNow(),
  proposalGenerated: integer("proposal_generated").notNull().default(0),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

export const insertFailurePatternSchema = createInsertSchema(failurePatternsTable).omit({ id: true, createdAt: true });
export type InsertFailurePattern = z.infer<typeof insertFailurePatternSchema>;
export type FailurePattern = typeof failurePatternsTable.$inferSelect;
