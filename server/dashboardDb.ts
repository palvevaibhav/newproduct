import { eq, and, gte, lte, desc } from "drizzle-orm";
import { getDb } from "./db";
import {
  packageMetrics,
  vulnerabilityTimeline,
  dashboardSnapshots,
  monitoredPackages,
} from "../drizzle/schema";

/**
 * Get package metrics for a date range
 */
export async function getPackageMetricsTrend(
  userId: number,
  packageId: number,
  startDate: Date,
  endDate: Date
) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");

  return await db
    .select()
    .from(packageMetrics)
    .where(
      and(
        eq(packageMetrics.userId, userId),
        eq(packageMetrics.packageId, packageId),
        gte(packageMetrics.metricsDate, startDate),
        lte(packageMetrics.metricsDate, endDate)
      )
    )
    .orderBy(packageMetrics.metricsDate);
}

/**
 * Get all package metrics for a user on a specific date
 */
export async function getPackageMetricsForDate(userId: number, date: Date) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");

  const startOfDay = new Date(date);
  startOfDay.setHours(0, 0, 0, 0);
  const endOfDay = new Date(date);
  endOfDay.setHours(23, 59, 59, 999);

  return await db
    .select()
    .from(packageMetrics)
    .where(
      and(
        eq(packageMetrics.userId, userId),
        gte(packageMetrics.metricsDate, startOfDay),
        lte(packageMetrics.metricsDate, endOfDay)
      )
    );
}

/**
 * Get vulnerability timeline for a package
 */
export async function getVulnerabilityTimeline(
  userId: number,
  packageId: number,
  startDate: Date,
  endDate: Date
) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");

  return await db
    .select()
    .from(vulnerabilityTimeline)
    .where(
      and(
        eq(vulnerabilityTimeline.userId, userId),
        eq(vulnerabilityTimeline.packageId, packageId),
        gte(vulnerabilityTimeline.discoveredAt, startDate),
        lte(vulnerabilityTimeline.discoveredAt, endDate)
      )
    )
    .orderBy(vulnerabilityTimeline.discoveredAt);
}

/**
 * Get all active vulnerabilities for a user's packages
 */
export async function getActiveVulnerabilities(userId: number) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");

  return await db
    .select()
    .from(vulnerabilityTimeline)
    .where(
      and(
        eq(vulnerabilityTimeline.userId, userId),
        eq(vulnerabilityTimeline.status, "active")
      )
    )
    .orderBy(desc(vulnerabilityTimeline.cvssScore));
}

/**
 * Get dashboard snapshot for a user
 */
export async function getDashboardSnapshot(userId: number, date?: Date) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");

  if (date) {
    const startOfDay = new Date(date);
    startOfDay.setHours(0, 0, 0, 0);
    const endOfDay = new Date(date);
    endOfDay.setHours(23, 59, 59, 999);

    const results = await db
      .select()
      .from(dashboardSnapshots)
      .where(
        and(
          eq(dashboardSnapshots.userId, userId),
          gte(dashboardSnapshots.snapshotDate, startOfDay),
          lte(dashboardSnapshots.snapshotDate, endOfDay)
        )
      );

    return results.length > 0 ? results[0] : null;
  }

  // Get latest snapshot
  const results = await db
    .select()
    .from(dashboardSnapshots)
    .where(eq(dashboardSnapshots.userId, userId))
    .orderBy(desc(dashboardSnapshots.snapshotDate))
    .limit(1);

  return results.length > 0 ? results[0] : null;
}

/**
 * Get dashboard snapshots for a date range
 */
export async function getDashboardSnapshotsTrend(
  userId: number,
  startDate: Date,
  endDate: Date
) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");

  return await db
    .select()
    .from(dashboardSnapshots)
    .where(
      and(
        eq(dashboardSnapshots.userId, userId),
        gte(dashboardSnapshots.snapshotDate, startDate),
        lte(dashboardSnapshots.snapshotDate, endDate)
      )
    )
    .orderBy(dashboardSnapshots.snapshotDate);
}

/**
 * Calculate health score based on vulnerability counts
 * Score: 100 - (critical*10 + high*5 + medium*2 + low*1)
 */
export function calculateHealthScore(
  criticalCount: number,
  highCount: number,
  mediumCount: number,
  lowCount: number
): number {
  const score = 100 - (criticalCount * 10 + highCount * 5 + mediumCount * 2 + lowCount * 1);
  return Math.max(0, Math.min(100, score));
}

/**
 * Determine risk level based on vulnerability counts
 */
export function determineRiskLevel(
  criticalCount: number,
  highCount: number,
  mediumCount: number
): string {
  if (criticalCount > 0) return "CRITICAL";
  if (highCount > 0) return "HIGH";
  if (mediumCount > 0) return "MEDIUM";
  return "LOW";
}

/**
 * Store package metrics
 */
export async function storePackageMetrics(
  userId: number,
  packageId: number,
  packageName: string,
  packageVersion: string | undefined,
  criticalCount: number,
  highCount: number,
  mediumCount: number,
  lowCount: number,
  maxCvssScore: string | undefined
) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");

  const totalVulnerabilities = criticalCount + highCount + mediumCount + lowCount;
  const healthScore = calculateHealthScore(criticalCount, highCount, mediumCount, lowCount);
  const riskLevel = determineRiskLevel(criticalCount, highCount, mediumCount);

  await db.insert(packageMetrics).values({
    userId,
    packageId,
    packageName,
    packageVersion,
    metricsDate: new Date(),
    criticalCount,
    highCount,
    mediumCount,
    lowCount,
    totalVulnerabilities,
    maxCvssScore,
    healthScore,
    riskLevel,
  });
}

/**
 * Store dashboard snapshot
 */
export async function storeDashboardSnapshot(
  userId: number,
  totalMonitoredPackages: number,
  packagesWithCritical: number,
  packagesWithHigh: number,
  packagesWithMedium: number,
  packagesWithLow: number,
  totalVulnerabilities: number,
  averageHealthScore: number,
  newVulnerabilitiesCount: number,
  fixedVulnerabilitiesCount: number
) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");

  const overallRiskLevel = packagesWithCritical > 0
    ? "CRITICAL"
    : packagesWithHigh > 0
      ? "HIGH"
      : packagesWithMedium > 0
        ? "MEDIUM"
        : "LOW";

  await db.insert(dashboardSnapshots).values({
    userId,
    snapshotDate: new Date(),
    totalMonitoredPackages,
    packagesWithCritical,
    packagesWithHigh,
    packagesWithMedium,
    packagesWithLow,
    totalVulnerabilities,
    averageHealthScore,
    overallRiskLevel,
    newVulnerabilitiesCount,
    fixedVulnerabilitiesCount,
  });
}

/**
 * Get vulnerability severity distribution for a user
 */
export async function getVulnerabilitySeverityDistribution(userId: number) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");

  const allVulnerabilities = await db
    .select()
    .from(vulnerabilityTimeline)
    .where(eq(vulnerabilityTimeline.userId, userId));

  const distribution = {
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0,
  };

  allVulnerabilities.forEach((v) => {
    const severity = (v.severity || "LOW") as keyof typeof distribution;
    if (severity in distribution) {
      distribution[severity]++;
    }
  });

  return distribution;
}

/**
 * Get package health scores for heatmap
 */
export async function getPackageHealthScores(userId: number) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");

  const packages = await db
    .select()
    .from(monitoredPackages)
    .where(eq(monitoredPackages.userId, userId));

  const healthData = await Promise.all(
    packages.map(async (pkg) => {
      const latestMetrics = await db
        .select()
        .from(packageMetrics)
        .where(
          and(
            eq(packageMetrics.userId, userId),
            eq(packageMetrics.packageId, pkg.id)
          )
        )
        .orderBy(desc(packageMetrics.metricsDate))
        .limit(1);

      return {
        packageName: pkg.packageName,
        packageVersion: pkg.packageVersion,
        healthScore: latestMetrics[0]?.healthScore || 100,
        riskLevel: latestMetrics[0]?.riskLevel || "LOW",
        totalVulnerabilities: latestMetrics[0]?.totalVulnerabilities || 0,
      };
    })
  );

  return healthData;
}
