import { pgTable, text, timestamp, uuid, boolean } from "drizzle-orm/pg-core";
import { sql } from "drizzle-orm";

export const userDomainsTable = pgTable("user_domains", {
  id: uuid("id").primaryKey().default(sql`gen_random_uuid()`),
  userId: uuid("user_id").notNull(),
  domain: text("domain").notNull(),
  verificationToken: text("verification_token").notNull(),
  isVerified: boolean("is_verified").notNull().default(false),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

export type UserDomain = typeof userDomainsTable.$inferSelect;
export type InsertUserDomain = typeof userDomainsTable.$inferInsert;
