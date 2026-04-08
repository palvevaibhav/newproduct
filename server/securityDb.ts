/**
 * Database helpers for security queries and vulnerability caching
 */

import { eq, and, desc, lt } from 'drizzle-orm';
import { getDb } from './db';
import {
  securityQueries,
  vulnerabilityCache,
  monitoredPackages,
  notificationHistory,
  InsertSecurityQuery,
  InsertVulnerabilityCache,
  InsertMonitoredPackage,
  InsertNotificationHistory,
  SecurityQuery,
  VulnerabilityCache,
} from '../drizzle/schema';
import { RAGResult } from './ragPipeline';
import { ClassificationResult, formatEntitiesForStorage } from './queryClassifier';

/**
 * Store a security query and its results in the database
 */
export async function storeSecurityQuery(
  userId: number,
  query: string,
  classification: ClassificationResult,
  ragResult: RAGResult
): Promise<SecurityQuery | null> {
  const db = await getDb();
  if (!db) return null;

  const entities = formatEntitiesForStorage(classification);
  const isCritical = ragResult.synthesis.riskLevel === 'CRITICAL';

  const queryData: InsertSecurityQuery = {
    userId,
    queryText: query,
    queryType: classification.queryType,
    detectedIntents: JSON.stringify(classification.detectedIntents),
    extractedEntities: JSON.stringify(entities),
    resultSummary: ragResult.synthesis.summary,
    fullResult: JSON.stringify(ragResult),
    isCritical,
    maxCvssScore: ragResult.synthesis.cvssScore?.toString() || null,
    queriedAt: new Date(),
  };

  try {
    const result = await db.insert(securityQueries).values(queryData);
    const insertedId = (result as any).insertId;
    
    if (insertedId) {
      return {
        id: insertedId,
        ...queryData,
        createdAt: new Date(),
        updatedAt: new Date(),
      } as SecurityQuery;
    }
  } catch (error) {
    console.error('Error storing security query:', error);
  }

  return null;
}

/**
 * Retrieve cached vulnerability data
 */
export async function getCachedVulnerability(identifier: string): Promise<VulnerabilityCache | null> {
  const db = await getDb();
  if (!db) return null;

  try {
    const result = await db
      .select()
      .from(vulnerabilityCache)
      .where(
        and(
          eq(vulnerabilityCache.identifier, identifier),
          lt(vulnerabilityCache.expiresAt || new Date(Date.now() + 24 * 60 * 60 * 1000), new Date())
        )
      )
      .limit(1);

    return result.length > 0 ? result[0] : null;
  } catch (error) {
    console.error('Error retrieving cached vulnerability:', error);
    return null;
  }
}

/**
 * Store vulnerability data in cache
 */
export async function cacheVulnerability(
  identifier: string,
  identifierType: 'cve' | 'ghsa' | 'package',
  sourceData: Record<string, unknown>,
  cvssScore: number | null,
  severity: string | null,
  affectedVersions: string[],
  fixedVersions: string[],
  references: Array<{ title: string; url: string }>
): Promise<VulnerabilityCache | null> {
  const db = await getDb();
  if (!db) return null;

  // Cache expires in 7 days
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

  const cacheData: InsertVulnerabilityCache = {
    identifier,
    identifierType,
    sourceData: JSON.stringify(sourceData),
    cvssScore: cvssScore?.toString() || null,
    severity,
    affectedVersions: JSON.stringify(affectedVersions),
    fixedVersions: JSON.stringify(fixedVersions),
    references: JSON.stringify(references),
    expiresAt,
  };

  try {
    await db.insert(vulnerabilityCache).values(cacheData).onDuplicateKeyUpdate({
      set: {
        sourceData: cacheData.sourceData,
        cvssScore: cacheData.cvssScore,
        severity: cacheData.severity,
        affectedVersions: cacheData.affectedVersions,
        fixedVersions: cacheData.fixedVersions,
        references: cacheData.references,
        expiresAt: cacheData.expiresAt,
        updatedAt: new Date(),
      },
    });

    return {
      id: 0, // Placeholder
      ...cacheData,
      lastFetched: new Date(),
      createdAt: new Date(),
      updatedAt: new Date(),
      nvdData: null,
      osvData: null,
      ghsaData: null,
      npmData: null,
      redhatData: null,
    } as VulnerabilityCache;
  } catch (error) {
    console.error('Error caching vulnerability:', error);
    return null;
  }
}

/**
 * Get recent security queries for a user
 */
export async function getRecentQueries(userId: number, limit: number = 10): Promise<SecurityQuery[]> {
  const db = await getDb();
  if (!db) return [];

  try {
    return await db
      .select()
      .from(securityQueries)
      .where(eq(securityQueries.userId, userId))
      .orderBy(desc(securityQueries.queriedAt))
      .limit(limit);
  } catch (error) {
    console.error('Error retrieving recent queries:', error);
    return [];
  }
}

/**
 * Get critical queries (CVSS > 8.0)
 */
export async function getCriticalQueries(userId: number, limit: number = 5): Promise<SecurityQuery[]> {
  const db = await getDb();
  if (!db) return [];

  try {
    return await db
      .select()
      .from(securityQueries)
      .where(
        and(
          eq(securityQueries.userId, userId),
          eq(securityQueries.isCritical, true)
        )
      )
      .orderBy(desc(securityQueries.queriedAt))
      .limit(limit);
  } catch (error) {
    console.error('Error retrieving critical queries:', error);
    return [];
  }
}

/**
 * Add a package to monitoring
 */
export async function addMonitoredPackage(
  userId: number,
  packageName: string,
  packageVersion?: string,
  ecosystem?: string
): Promise<void> {
  const db = await getDb();
  if (!db) return;

  const packageData: InsertMonitoredPackage = {
    userId,
    packageName,
    packageVersion: packageVersion || null,
    ecosystem: ecosystem || 'npm',
  };

  try {
    await db.insert(monitoredPackages).values(packageData);
  } catch (error) {
    console.error('Error adding monitored package:', error);
  }
}

/**
 * Get monitored packages for a user
 */
export async function getMonitoredPackages(userId: number) {
  const db = await getDb();
  if (!db) return [];

  try {
    return await db
      .select()
      .from(monitoredPackages)
      .where(eq(monitoredPackages.userId, userId));
  } catch (error) {
    console.error('Error retrieving monitored packages:', error);
    return [];
  }
}

/**
 * Record a notification
 */
export async function recordNotification(
  userId: number,
  notificationType: 'critical_cve' | 'high_severity' | 'package_vulnerability',
  title: string,
  content: string,
  cvssScore?: number | null,
  relatedCveId?: string,
  queryId?: number
): Promise<void> {
  const db = await getDb();
  if (!db) return;

  const notificationData: InsertNotificationHistory = {
    userId,
    queryId: queryId || null,
    notificationType,
    title,
    content,
    cvssScore: cvssScore?.toString() || null,
    relatedCveId: relatedCveId || null,
  };

  try {
    await db.insert(notificationHistory).values(notificationData);
  } catch (error) {
    console.error('Error recording notification:', error);
  }
}

/**
 * Get notification history for a user
 */
export async function getNotificationHistory(userId: number, limit: number = 20) {
  const db = await getDb();
  if (!db) return [];

  try {
    return await db
      .select()
      .from(notificationHistory)
      .where(eq(notificationHistory.userId, userId))
      .orderBy(desc(notificationHistory.sentAt))
      .limit(limit);
  } catch (error) {
    console.error('Error retrieving notification history:', error);
    return [];
  }
}
