/**
 * Query Classifier: Detects input type and extracts entities from security queries
 * Supports: CVE IDs, GHSA IDs, package names, versions, vulnerability types, natural language
 */

export type QueryType = 'cve' | 'ghsa' | 'package' | 'vulnerability_type' | 'natural_language';

export interface DetectedEntity {
  type: 'cve' | 'ghsa' | 'package' | 'version' | 'vulnerability_type';
  value: string;
  confidence: number; // 0-1
}

export interface ClassificationResult {
  queryType: QueryType;
  detectedIntents: string[];
  entities: DetectedEntity[];
  primaryEntity: DetectedEntity | null;
  isSecurityRelated: boolean;
  confidence: number;
}

// Regex patterns for entity detection
const CVE_PATTERN = /CVE-\d{4}-\d{4,}/gi;
const GHSA_PATTERN = /GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}/gi;
const PACKAGE_PATTERN = /^[@a-z0-9][a-z0-9\-._@/]*$/i; // npm package name pattern
const VERSION_PATTERN = /\b(\d+\.\d+(?:\.\d+)?(?:-[a-zA-Z0-9.]+)?)\b/g;
const VULNERABILITY_KEYWORDS = [
  'sql injection', 'xss', 'cross-site scripting', 'rce', 'remote code execution',
  'buffer overflow', 'dos', 'denial of service', 'privilege escalation', 'authentication bypass',
  'authorization bypass', 'information disclosure', 'arbitrary code execution', 'injection',
  'path traversal', 'xxe', 'xml external entity', 'csrf', 'cross-site request forgery',
  'clickjacking', 'insecure deserialization', 'broken authentication', 'sensitive data exposure',
  'xml bomb', 'zip bomb', 'prototype pollution', 'command injection', 'ldap injection',
  'os command injection', 'race condition', 'use-after-free', 'memory leak',
];

/**
 * Classify a security query and extract entities
 */
export function classifyQuery(query: string): ClassificationResult {
  const normalizedQuery = query.trim();
  const lowerQuery = normalizedQuery.toLowerCase();
  const entities: DetectedEntity[] = [];

  // Extract CVE IDs
  const cveMatches = normalizedQuery.match(CVE_PATTERN);
  if (cveMatches) {
    cveMatches.forEach((cve) => {
      entities.push({
        type: 'cve',
        value: cve.toUpperCase(),
        confidence: 1.0,
      });
    });
  }

  // Extract GHSA IDs
  const ghsaMatches = normalizedQuery.match(GHSA_PATTERN);
  if (ghsaMatches) {
    ghsaMatches.forEach((ghsa) => {
      entities.push({
        type: 'ghsa',
        value: ghsa.toUpperCase(),
        confidence: 1.0,
      });
    });
  }

  // Detect vulnerability types
  const detectedVulnTypes: DetectedEntity[] = [];
  for (const keyword of VULNERABILITY_KEYWORDS) {
    if (lowerQuery.includes(keyword)) {
      detectedVulnTypes.push({
        type: 'vulnerability_type',
        value: keyword,
        confidence: 0.9,
      });
    }
  }
  entities.push(...detectedVulnTypes);

  // Extract versions (look for semantic versioning patterns)
  const versionMatches = normalizedQuery.match(VERSION_PATTERN);
  if (versionMatches) {
    const uniqueVersions = Array.from(new Set(versionMatches));
    uniqueVersions.forEach((version) => {
      entities.push({
        type: 'version',
        value: version,
        confidence: 0.8,
      });
    });
  }

  // Try to detect package names (heuristic: words that look like package names)
  const words = normalizedQuery.split(/[\s,;:()[\]{}]/);
  for (const word of words) {
    const cleanWord = word.replace(/[^\w\-@/.]/g, '');
    if (cleanWord.length > 2 && cleanWord.length < 100 && PACKAGE_PATTERN.test(cleanWord)) {
      // Check if it's not a known keyword
      const isNotKeyword = !['and', 'the', 'for', 'with', 'from', 'to', 'in', 'is', 'are', 'was', 'be', 'have', 'has', 'do', 'does', 'did', 'will', 'would', 'could', 'should', 'may', 'might', 'must', 'can', 'of', 'or', 'not', 'no', 'yes', 'as', 'at', 'by', 'on', 'up', 'out', 'if', 'about', 'into', 'through', 'during', 'before', 'after', 'above', 'below', 'between', 'under', 'again', 'further', 'then', 'once', 'here', 'there', 'when', 'where', 'why', 'how', 'all', 'each', 'every', 'both', 'few', 'more', 'most', 'other', 'some', 'such', 'only', 'own', 'same', 'so', 'than', 'too', 'very', 's', 't', 'can', 'just', 'don', 'now'].includes(cleanWord.toLowerCase());
      
      if (isNotKeyword && !entities.some((e) => e.type === 'package' && e.value === cleanWord)) {
        entities.push({
          type: 'package',
          value: cleanWord,
          confidence: 0.6,
        });
      }
    }
  }

  // Determine query type based on detected entities
  let queryType: QueryType = 'natural_language';
  let primaryEntity: DetectedEntity | null = null;

  if (entities.length > 0) {
    // Sort by confidence and type priority
    const sorted = entities.sort((a, b) => {
      const typePriority: Record<string, number> = {
        cve: 10,
        ghsa: 9,
        package: 8,
        version: 5,
        vulnerability_type: 7,
      };
      const aPriority = typePriority[a.type] || 0;
      const bPriority = typePriority[b.type] || 0;
      return b.confidence * bPriority - a.confidence * aPriority;
    });

    primaryEntity = sorted[0];

    if (primaryEntity.type === 'cve') {
      queryType = 'cve';
    } else if (primaryEntity.type === 'ghsa') {
      queryType = 'ghsa';
    } else if (primaryEntity.type === 'package') {
      queryType = 'package';
    } else if (primaryEntity.type === 'vulnerability_type') {
      queryType = 'vulnerability_type';
    }
  }

  // Detect intents
  const intents: string[] = [];
  if (lowerQuery.includes('safe') || lowerQuery.includes('vulnerable') || lowerQuery.includes('affected')) {
    intents.push('risk_assessment');
  }
  if (lowerQuery.includes('fix') || lowerQuery.includes('patch') || lowerQuery.includes('update')) {
    intents.push('remediation');
  }
  if (lowerQuery.includes('compare') || lowerQuery.includes('vs') || lowerQuery.includes('difference')) {
    intents.push('comparison');
  }
  if (lowerQuery.includes('history') || lowerQuery.includes('timeline') || lowerQuery.includes('when')) {
    intents.push('history');
  }
  if (intents.length === 0) {
    intents.push('information_retrieval');
  }

  // Determine if security-related
  const isSecurityRelated = entities.length > 0 || 
    VULNERABILITY_KEYWORDS.some((keyword) => lowerQuery.includes(keyword)) ||
    lowerQuery.includes('security') ||
    lowerQuery.includes('vulnerability') ||
    lowerQuery.includes('cve') ||
    lowerQuery.includes('ghsa') ||
    lowerQuery.includes('exploit') ||
    lowerQuery.includes('patch') ||
    lowerQuery.includes('vulnerable');

  // Calculate overall confidence
  const confidence = entities.length > 0 
    ? Math.min(1.0, entities.reduce((sum, e) => sum + e.confidence, 0) / Math.max(1, entities.length))
    : (isSecurityRelated ? 0.6 : 0.3);

  return {
    queryType,
    detectedIntents: intents,
    entities,
    primaryEntity,
    isSecurityRelated,
    confidence,
  };
}

/**
 * Extract specific entity types from classification result
 */
export function extractEntitiesByType(result: ClassificationResult, type: DetectedEntity['type']): string[] {
  return result.entities
    .filter((e) => e.type === type)
    .map((e) => e.value)
    .filter((v, i, a) => a.indexOf(v) === i); // unique
}

/**
 * Format entities for database storage
 */
export function formatEntitiesForStorage(result: ClassificationResult): Record<string, string[]> {
  return {
    cveIds: extractEntitiesByType(result, 'cve'),
    ghsaIds: extractEntitiesByType(result, 'ghsa'),
    packages: extractEntitiesByType(result, 'package'),
    versions: extractEntitiesByType(result, 'version'),
    vulnerabilityTypes: extractEntitiesByType(result, 'vulnerability_type'),
  };
}
