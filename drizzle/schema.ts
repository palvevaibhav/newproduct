import { boolean, int, mysqlEnum, mysqlTable, text, timestamp, varchar } from "drizzle-orm/mysql-core";

/**
 * Core user table backing auth flow.
 * Extend this file with additional tables as your product grows.
 * Columns use camelCase to match both database fields and generated types.
 */
export const users = mysqlTable("users", {
  /**
   * Surrogate primary key. Auto-incremented numeric value managed by the database.
   * Use this for relations between tables.
   */
  id: int("id").autoincrement().primaryKey(),
  /** Manus OAuth identifier (openId) returned from the OAuth callback. Unique per user. */
  openId: varchar("openId", { length: 64 }).notNull().unique(),
  name: text("name"),
  email: varchar("email", { length: 320 }),
  loginMethod: varchar("loginMethod", { length: 64 }),
  role: mysqlEnum("role", ["user", "admin"]).default("user").notNull(),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
  lastSignedIn: timestamp("lastSignedIn").defaultNow().notNull(),
});

export type User = typeof users.$inferSelect;
export type InsertUser = typeof users.$inferInsert;

/**
 * Queries table: stores all security queries and their cached results
 */
export const securityQueries = mysqlTable("security_queries", {
  id: int("id").autoincrement().primaryKey(),
  userId: int("userId").notNull().references(() => users.id),
  queryText: text("queryText").notNull(),
  queryType: varchar("queryType", { length: 50 }).notNull(), // 'cve', 'package', 'vulnerability_type', 'natural_language'
  detectedIntents: text("detectedIntents"), // JSON array of detected intents
  extractedEntities: text("extractedEntities"), // JSON: {cveIds: [], packages: [], versions: [], etc}
  resultSummary: text("resultSummary"), // LLM-synthesized summary
  fullResult: text("fullResult"), // Full JSON result from RAG pipeline
  isCritical: boolean("isCritical").default(false), // CVSS > 8.0
  maxCvssScore: varchar("maxCvssScore", { length: 10 }),
  queriedAt: timestamp("queriedAt").defaultNow().notNull(),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
});

export type SecurityQuery = typeof securityQueries.$inferSelect;
export type InsertSecurityQuery = typeof securityQueries.$inferInsert;

/**
 * Vulnerability cache: stores fetched vulnerability data from various sources
 */
export const vulnerabilityCache = mysqlTable("vulnerability_cache", {
  id: int("id").autoincrement().primaryKey(),
  identifier: varchar("identifier", { length: 255 }).notNull().unique(), // CVE-ID, GHSA-ID, or package:version
  identifierType: varchar("identifierType", { length: 50 }).notNull(), // 'cve', 'ghsa', 'package'
  sourceData: text("sourceData"), // JSON: aggregated data from all sources
  nvdData: text("nvdData"), // JSON from NVD
  osvData: text("osvData"), // JSON from OSV
  ghsaData: text("ghsaData"), // JSON from GHSA
  npmData: text("npmData"), // JSON from NPM
  redhatData: text("redhatData"), // JSON from Red Hat
  cvssScore: varchar("cvssScore", { length: 10 }),
  severity: varchar("severity", { length: 50 }), // 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'
  affectedVersions: text("affectedVersions"), // JSON array
  fixedVersions: text("fixedVersions"), // JSON array
  references: text("references"), // JSON array of reference URLs
  lastFetched: timestamp("lastFetched").defaultNow().notNull(),
  expiresAt: timestamp("expiresAt"), // Cache expiration time
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
});

export type VulnerabilityCache = typeof vulnerabilityCache.$inferSelect;
export type InsertVulnerabilityCache = typeof vulnerabilityCache.$inferInsert;

/**
 * Monitored packages: for tracking packages users want to monitor for vulnerabilities
 */
export const monitoredPackages = mysqlTable("monitored_packages", {
  id: int("id").autoincrement().primaryKey(),
  userId: int("userId").notNull().references(() => users.id),
  packageName: varchar("packageName", { length: 255 }).notNull(),
  packageVersion: varchar("packageVersion", { length: 100 }),
  ecosystem: varchar("ecosystem", { length: 50 }), // 'npm', 'pypi', 'maven', etc
  lastChecked: timestamp("lastChecked"),
  knownVulnerabilities: text("knownVulnerabilities"), // JSON array of CVE IDs
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
});

export type MonitoredPackage = typeof monitoredPackages.$inferSelect;
export type InsertMonitoredPackage = typeof monitoredPackages.$inferInsert;

/**
 * Notification history: tracks sent notifications about critical CVEs
 */
export const notificationHistory = mysqlTable("notification_history", {
  id: int("id").autoincrement().primaryKey(),
  userId: int("userId").notNull().references(() => users.id),
  queryId: int("queryId").references(() => securityQueries.id),
  notificationType: varchar("notificationType", { length: 50 }).notNull(), // 'critical_cve', 'high_severity', 'package_vulnerability'
  title: varchar("title", { length: 255 }).notNull(),
  content: text("content"),
  cvssScore: varchar("cvssScore", { length: 10 }),
  relatedCveId: varchar("relatedCveId", { length: 50 }),
  sentAt: timestamp("sentAt").defaultNow().notNull(),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
});

export type NotificationHistory = typeof notificationHistory.$inferSelect;
export type InsertNotificationHistory = typeof notificationHistory.$inferInsert;

/**
 * Package metrics: daily security metrics for monitored packages
 */
export const packageMetrics = mysqlTable("package_metrics", {
  id: int("id").autoincrement().primaryKey(),
  userId: int("userId").notNull().references(() => users.id),
  packageId: int("packageId").notNull().references(() => monitoredPackages.id),
  packageName: varchar("packageName", { length: 255 }).notNull(),
  packageVersion: varchar("packageVersion", { length: 100 }),
  metricsDate: timestamp("metricsDate").notNull(),
  criticalCount: int("criticalCount").default(0),
  highCount: int("highCount").default(0),
  mediumCount: int("mediumCount").default(0),
  lowCount: int("lowCount").default(0),
  totalVulnerabilities: int("totalVulnerabilities").default(0),
  maxCvssScore: varchar("maxCvssScore", { length: 10 }),
  healthScore: int("healthScore"),
  riskLevel: varchar("riskLevel", { length: 50 }),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
});

export type PackageMetrics = typeof packageMetrics.$inferSelect;
export type InsertPackageMetrics = typeof packageMetrics.$inferInsert;

/**
 * Vulnerability timeline: tracks when vulnerabilities are discovered/fixed
 */
export const vulnerabilityTimeline = mysqlTable("vulnerability_timeline", {
  id: int("id").autoincrement().primaryKey(),
  userId: int("userId").notNull().references(() => users.id),
  packageId: int("packageId").references(() => monitoredPackages.id),
  cveId: varchar("cveId", { length: 50 }).notNull(),
  packageName: varchar("packageName", { length: 255 }),
  affectedVersion: varchar("affectedVersion", { length: 100 }),
  discoveredAt: timestamp("discoveredAt").notNull(),
  fixedAt: timestamp("fixedAt"),
  fixedVersion: varchar("fixedVersion", { length: 100 }),
  cvssScore: varchar("cvssScore", { length: 10 }),
  severity: varchar("severity", { length: 50 }),
  status: varchar("status", { length: 50 }),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
});

export type VulnerabilityTimeline = typeof vulnerabilityTimeline.$inferSelect;
export type InsertVulnerabilityTimeline = typeof vulnerabilityTimeline.$inferInsert;

/**
 * Dashboard snapshots: periodic snapshots of overall security posture
 */
export const dashboardSnapshots = mysqlTable("dashboard_snapshots", {
  id: int("id").autoincrement().primaryKey(),
  userId: int("userId").notNull().references(() => users.id),
  snapshotDate: timestamp("snapshotDate").notNull(),
  totalMonitoredPackages: int("totalMonitoredPackages"),
  packagesWithCritical: int("packagesWithCritical"),
  packagesWithHigh: int("packagesWithHigh"),
  packagesWithMedium: int("packagesWithMedium"),
  packagesWithLow: int("packagesWithLow"),
  totalVulnerabilities: int("totalVulnerabilities"),
  averageHealthScore: int("averageHealthScore"),
  overallRiskLevel: varchar("overallRiskLevel", { length: 50 }),
  newVulnerabilitiesCount: int("newVulnerabilitiesCount"),
  fixedVulnerabilitiesCount: int("fixedVulnerabilitiesCount"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
});

export type DashboardSnapshot = typeof dashboardSnapshots.$inferSelect;
export type InsertDashboardSnapshot = typeof dashboardSnapshots.$inferInsert;
