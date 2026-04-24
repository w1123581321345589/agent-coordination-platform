import { pgTable, text, serial, timestamp, integer, real } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod/v4";

export const tournamentsTable = pgTable("tournaments", {
  id: serial("id").primaryKey(),
  taskDescription: text("task_description").notNull(),
  domain: text("domain").notNull(),
  taskType: text("task_type").notNull(),
  status: text("status").notNull().default("running"),
  winnerId: integer("winner_id"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow().$onUpdate(() => new Date()),
});

export const insertTournamentSchema = createInsertSchema(tournamentsTable).omit({ id: true, createdAt: true, updatedAt: true });
export type InsertTournament = z.infer<typeof insertTournamentSchema>;
export type Tournament = typeof tournamentsTable.$inferSelect;

export const tournamentVariantsTable = pgTable("tournament_variants", {
  id: serial("id").primaryKey(),
  tournamentId: integer("tournament_id").notNull(),
  pattern: text("pattern").notNull(),
  qualityScore: real("quality_score"),
  efficiencyScore: real("efficiency_score"),
  costScore: real("cost_score"),
  compositeScore: real("composite_score"),
  winner: integer("winner").notNull().default(0),
});

export const insertTournamentVariantSchema = createInsertSchema(tournamentVariantsTable).omit({ id: true });
export type InsertTournamentVariant = z.infer<typeof insertTournamentVariantSchema>;
export type TournamentVariant = typeof tournamentVariantsTable.$inferSelect;
