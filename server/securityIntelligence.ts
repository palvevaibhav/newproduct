import { promisify } from 'node:util';
import { execFile } from 'node:child_process';
import { fetchFromAllSources } from './dataFetchers';

const execFileAsync = promisify(execFile);

type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';

export interface NormalizedVulnRecord {
  id: string;
  aliases: string[];
  source: string;
  packageName?: string;
  ecosystem?: string;
  summary?: string;
  details?: string;
  severity: Severity;
  cvssScore: number | null;
  introducedVersions: string[];
  fixedVersions: string[];
  references: string[];
}

export interface VersionCorrelationResult {
  packageName: string;
  packageVersion?: string;
  vulnerable: boolean;
  matchedVulnerabilities: Array<{
    id: string;
    source: string;
    severity: Severity;
    cvssScore: number | null;
    fixedVersions: string[];
    introducedVersions: string[];
  }>;
}

export interface LibraryRiskReport {
  packageName: string;
  packageVersion?: string;
  ingestedSources: string[];
  vulnerabilityCount: number;
  vulnerabilities: NormalizedVulnRecord[];
  versionCorrelation: VersionCorrelationResult;
  extractedPatches: Array<{
    vulnerabilityId: string;
    patchUrls: string[];
  }>;
  riskScore: {
    score: number;
    level: Severity;
    rationale: string[];
  };
}

export interface PatchAnalysisResult {
  commitHash: string;
  title: string;
  filesChanged: string[];
  inferredVulnerabilities: string[];
  affectedVersions: string[];
  riskExplanation: string;
}

export interface CveIntelRecord {
  id: string;
  aliases: string[];
  severity: Severity;
  cvssScore: number | null;
  summary?: string;
  details?: string;
  publishedAt?: string;
  references: string[];
  sources: string[];
}

export interface CveIntelReport {
  cveId: string;
  found: boolean;
  ingestedSources: string[];
  records: CveIntelRecord[];
  riskScore: {
    score: number;
    level: Severity;
    rationale: string[];
  };
}

const cvePattern = /CVE-\d{4}-\d{4,}/gi;
const ghsaPattern = /GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}/gi;

function toSeverity(score: number | null): Severity {
  if (score === null) return 'UNKNOWN';
  if (score >= 9) return 'CRITICAL';
  if (score >= 7) return 'HIGH';
  if (score >= 4) return 'MEDIUM';
  return 'LOW';
}

function parseSemver(version: string): [number, number, number] | null {
  const match = version.trim().match(/^(\d+)\.(\d+)(?:\.(\d+))?/);
  if (!match) return null;
  return [Number(match[1]), Number(match[2]), Number(match[3] || 0)];
}

function compareSemver(a: string, b: string): number {
  const pa = parseSemver(a);
  const pb = parseSemver(b);
  if (!pa || !pb) return 0;

  for (let i = 0; i < 3; i += 1) {
    if (pa[i] > pb[i]) return 1;
    if (pa[i] < pb[i]) return -1;
  }

  return 0;
}

function normalizeOSVVuln(vuln: Record<string, unknown>): NormalizedVulnRecord {
  const affectedEntries = Array.isArray(vuln.affected) ? vuln.affected : [];
  const introducedVersions: string[] = [];
  const fixedVersions: string[] = [];
  let packageName: string | undefined;
  let ecosystem: string | undefined;

  for (const entry of affectedEntries) {
    if (typeof entry !== 'object' || entry === null) continue;
    const affected = entry as Record<string, unknown>;

    if (typeof affected.package === 'object' && affected.package !== null) {
      const pkg = affected.package as Record<string, unknown>;
      if (typeof pkg.name === 'string') packageName = pkg.name;
      if (typeof pkg.ecosystem === 'string') ecosystem = pkg.ecosystem;
    }

    if (!Array.isArray(affected.ranges)) continue;
    for (const range of affected.ranges) {
      if (typeof range !== 'object' || range === null) continue;
      const rangeObj = range as Record<string, unknown>;
      if (!Array.isArray(rangeObj.events)) continue;
      for (const event of rangeObj.events) {
        if (typeof event !== 'object' || event === null) continue;
        const eventObj = event as Record<string, unknown>;
        if (typeof eventObj.introduced === 'string') introducedVersions.push(eventObj.introduced);
        if (typeof eventObj.fixed === 'string') fixedVersions.push(eventObj.fixed);
      }
    }
  }

  let cvssScore: number | null = null;
  if (Array.isArray(vuln.severity)) {
    for (const sev of vuln.severity) {
      if (typeof sev !== 'object' || sev === null) continue;
      const scoreText = (sev as Record<string, unknown>).score;
      if (typeof scoreText === 'string') {
        const match = scoreText.match(/(\d+\.?\d*)/);
        if (match) {
          cvssScore = Number(match[1]);
          break;
        }
      }
    }
  }

  const aliases = Array.isArray(vuln.aliases)
    ? vuln.aliases.filter((x): x is string => typeof x === 'string')
    : [];

  const references = Array.isArray(vuln.references)
    ? vuln.references
      .map((r) => (typeof r === 'object' && r !== null ? (r as Record<string, unknown>).url : null))
      .filter((x): x is string => typeof x === 'string')
    : [];

  return {
    id: typeof vuln.id === 'string' ? vuln.id : aliases[0] || 'UNKNOWN',
    aliases,
    source: 'OSV',
    packageName,
    ecosystem,
    summary: typeof vuln.summary === 'string' ? vuln.summary : undefined,
    details: typeof vuln.details === 'string' ? vuln.details : undefined,
    severity: toSeverity(cvssScore),
    cvssScore,
    introducedVersions: Array.from(new Set(introducedVersions)),
    fixedVersions: Array.from(new Set(fixedVersions)),
    references: Array.from(new Set(references)),
  };
}

function readCvssFromNvd(vuln: Record<string, unknown>): number | null {
  const cve = typeof vuln.cve === 'object' && vuln.cve !== null
    ? vuln.cve as Record<string, unknown>
    : null;
  const metrics = cve && typeof cve.metrics === 'object' && cve.metrics !== null
    ? cve.metrics as Record<string, unknown>
    : null;
  if (!metrics) return null;

  const vectors = [
    metrics.cvssMetricV31,
    metrics.cvssMetricV30,
    metrics.cvssMetricV2,
  ];

  for (const vector of vectors) {
    if (!Array.isArray(vector) || vector.length === 0) continue;
    const first = vector[0];
    if (typeof first !== 'object' || first === null) continue;
    const cvssData = (first as Record<string, unknown>).cvssData;
    if (typeof cvssData !== 'object' || cvssData === null) continue;
    const baseScore = (cvssData as Record<string, unknown>).baseScore;
    if (typeof baseScore === 'number') return baseScore;
  }

  return null;
}

function normalizeNvdCve(vuln: Record<string, unknown>): CveIntelRecord | null {
  const cve = typeof vuln.cve === 'object' && vuln.cve !== null
    ? vuln.cve as Record<string, unknown>
    : null;
  if (!cve) return null;

  const id = typeof cve.id === 'string' ? cve.id.toUpperCase() : undefined;
  if (!id) return null;

  const descriptions = Array.isArray(cve.descriptions)
    ? cve.descriptions
    : [];
  const englishDescription = descriptions.find((item) => {
    if (typeof item !== 'object' || item === null) return false;
    return (item as Record<string, unknown>).lang === 'en';
  }) as Record<string, unknown> | undefined;

  const refs = Array.isArray(cve.references)
    ? cve.references
      .map((entry) => {
        if (typeof entry !== 'object' || entry === null) return null;
        const url = (entry as Record<string, unknown>).url;
        return typeof url === 'string' ? url : null;
      })
      .filter((x): x is string => Boolean(x))
    : [];

  const cvssScore = readCvssFromNvd(vuln);

  return {
    id,
    aliases: [],
    severity: toSeverity(cvssScore),
    cvssScore,
    summary: typeof englishDescription?.value === 'string' ? englishDescription.value : undefined,
    details: typeof englishDescription?.value === 'string' ? englishDescription.value : undefined,
    publishedAt: typeof cve.published === 'string' ? cve.published : undefined,
    references: Array.from(new Set(refs)),
    sources: ['NVD'],
  };
}

function mergeCveRecords(records: CveIntelRecord[]): CveIntelRecord[] {
  const byId = new Map<string, CveIntelRecord>();

  for (const record of records) {
    const existing = byId.get(record.id);
    if (!existing) {
      byId.set(record.id, { ...record });
      continue;
    }

    byId.set(record.id, {
      ...existing,
      aliases: Array.from(new Set([...existing.aliases, ...record.aliases])),
      severity: existing.cvssScore !== null && (record.cvssScore === null || existing.cvssScore >= record.cvssScore)
        ? existing.severity
        : record.severity,
      cvssScore: existing.cvssScore !== null ? Math.max(existing.cvssScore, record.cvssScore ?? 0) : record.cvssScore,
      summary: existing.summary ?? record.summary,
      details: existing.details ?? record.details,
      publishedAt: existing.publishedAt ?? record.publishedAt,
      references: Array.from(new Set([...existing.references, ...record.references])),
      sources: Array.from(new Set([...existing.sources, ...record.sources])),
    });
  }

  return Array.from(byId.values());
}

export async function buildCveIntelReport(cveId: string): Promise<CveIntelReport> {
  const normalizedId = cveId.trim().toUpperCase();
  if (!/^CVE-\d{4}-\d{4,}$/.test(normalizedId)) {
    throw new Error('Invalid CVE ID format. Expected CVE-YYYY-NNNN');
  }

  const sourceResults = await fetchFromAllSources(normalizedId, 'cve');
  const ingestedSources = sourceResults.successfulResults.map((result) => result.source);

  const records: CveIntelRecord[] = [];

  if (sourceResults.aggregatedData.nvd && typeof sourceResults.aggregatedData.nvd === 'object') {
    const nvdRecord = normalizeNvdCve(sourceResults.aggregatedData.nvd as Record<string, unknown>);
    if (nvdRecord) {
      records.push(nvdRecord);
    }
  }

  if (Array.isArray(sourceResults.aggregatedData.osv)) {
    for (const vuln of sourceResults.aggregatedData.osv as Record<string, unknown>[]) {
      const normalized = normalizeOSVVuln(vuln);
      const ids = [normalized.id, ...normalized.aliases].map((id) => id.toUpperCase());
      if (!ids.includes(normalizedId)) continue;
      records.push({
        id: normalizedId,
        aliases: normalized.aliases,
        severity: normalized.severity,
        cvssScore: normalized.cvssScore,
        summary: normalized.summary,
        details: normalized.details,
        references: normalized.references,
        sources: [normalized.source],
      });
    }
  }

  const mergedRecords = mergeCveRecords(records);
  const riskScore = computeRiskScore(
    mergedRecords.map((record) => ({
      id: record.id,
      aliases: record.aliases,
      source: record.sources.join(','),
      severity: record.severity,
      cvssScore: record.cvssScore,
      introducedVersions: [],
      fixedVersions: [],
      references: record.references,
    })),
    mergedRecords.some((record) => record.references.some((ref) => /commit|pull|patch|changelog|release/i.test(ref))),
  );

  return {
    cveId: normalizedId,
    found: mergedRecords.length > 0,
    ingestedSources,
    records: mergedRecords,
    riskScore,
  };
}

export function correlateVersion(
  packageName: string,
  packageVersion: string | undefined,
  vulnerabilities: NormalizedVulnRecord[],
): VersionCorrelationResult {
  const lowerPackage = packageName.toLowerCase();
  const relevant = vulnerabilities.filter((v) => v.packageName?.toLowerCase() === lowerPackage);

  const matchedVulnerabilities = relevant.filter((v) => {
    if (!packageVersion) return true;
    if (v.fixedVersions.length === 0) return true;

    return v.fixedVersions.some((fixed) => compareSemver(packageVersion, fixed) < 0);
  });

  return {
    packageName,
    packageVersion,
    vulnerable: matchedVulnerabilities.length > 0,
    matchedVulnerabilities: matchedVulnerabilities.map((v) => ({
      id: v.id,
      source: v.source,
      severity: v.severity,
      cvssScore: v.cvssScore,
      fixedVersions: v.fixedVersions,
      introducedVersions: v.introducedVersions,
    })),
  };
}

export function computeRiskScore(vulnerabilities: NormalizedVulnRecord[], hasKnownPatch: boolean): LibraryRiskReport['riskScore'] {
  if (vulnerabilities.length === 0) {
    return {
      score: 0,
      level: 'LOW',
      rationale: ['No vulnerabilities were found across ingested sources.'],
    };
  }

  const maxCvss = vulnerabilities.reduce((max, vuln) => Math.max(max, vuln.cvssScore ?? 0), 0);
  const criticalCount = vulnerabilities.filter((v) => v.severity === 'CRITICAL').length;
  const highCount = vulnerabilities.filter((v) => v.severity === 'HIGH').length;

  let score = Math.round(maxCvss * 10);
  score += criticalCount * 8;
  score += highCount * 4;
  if (!hasKnownPatch) score += 10;
  score = Math.min(100, score);

  const level = score >= 80 ? 'CRITICAL' : score >= 60 ? 'HIGH' : score >= 30 ? 'MEDIUM' : 'LOW';

  return {
    score,
    level,
    rationale: [
      `Max CVSS considered: ${maxCvss.toFixed(1)}.`,
      `${criticalCount} critical and ${highCount} high severity records detected.`,
      hasKnownPatch
        ? 'At least one patch or fix reference was found.'
        : 'No explicit patch references detected; remediation uncertainty increases risk.',
    ],
  };
}

function extractPatchCandidates(vulnerabilities: NormalizedVulnRecord[]) {
  return vulnerabilities
    .map((vuln) => ({
      vulnerabilityId: vuln.id,
      patchUrls: vuln.references.filter((url) => /commit|pull|patch|changelog|release/i.test(url)),
    }))
    .filter((vuln) => vuln.patchUrls.length > 0);
}

export async function buildLibraryRiskReport(packageName: string, packageVersion?: string): Promise<LibraryRiskReport> {
  const sourceResults = await fetchFromAllSources(packageName, 'package');
  const ingestedSources = sourceResults.successfulResults.map((result) => result.source);
  const osvData = Array.isArray(sourceResults.aggregatedData.osv)
    ? sourceResults.aggregatedData.osv
    : [];

  const vulnerabilities = (osvData as Record<string, unknown>[]).map(normalizeOSVVuln);
  const versionCorrelation = correlateVersion(packageName, packageVersion, vulnerabilities);
  const extractedPatches = extractPatchCandidates(versionCorrelation.matchedVulnerabilities.map((match) => {
    const full = vulnerabilities.find((v) => v.id === match.id);
    return full ?? {
      id: match.id,
      aliases: [],
      source: match.source,
      severity: match.severity,
      cvssScore: match.cvssScore,
      introducedVersions: match.introducedVersions,
      fixedVersions: match.fixedVersions,
      references: [],
    };
  }));

  return {
    packageName,
    packageVersion,
    ingestedSources,
    vulnerabilityCount: vulnerabilities.length,
    vulnerabilities,
    versionCorrelation,
    extractedPatches,
    riskScore: computeRiskScore(versionCorrelation.matchedVulnerabilities.map((match) => {
      const full = vulnerabilities.find((v) => v.id === match.id);
      return full ?? {
        id: match.id,
        aliases: [],
        source: match.source,
        severity: match.severity,
        cvssScore: match.cvssScore,
        introducedVersions: match.introducedVersions,
        fixedVersions: match.fixedVersions,
        references: [],
      };
    }), extractedPatches.length > 0),
  };
}

export async function analyzePatchCommit(commitHash: string): Promise<PatchAnalysisResult> {
  const { stdout } = await execFileAsync('git', ['show', '--quiet', '--name-only', '--format=%H%n%s%n%b', commitHash]);
  const lines = stdout.split('\n').map((line) => line.trim()).filter(Boolean);

  if (lines.length < 2) {
    throw new Error(`Unable to parse commit ${commitHash}`);
  }

  const [fullHash, title, ...rest] = lines;
  const filesChanged = rest.filter((line) => line.includes('.') && !line.startsWith('CVE-') && !line.startsWith('GHSA-'));

  const joined = rest.join('\n');
  const inferredVulnerabilities = Array.from(new Set([
    ...(title.match(cvePattern) ?? []),
    ...(joined.match(cvePattern) ?? []),
    ...(title.match(ghsaPattern) ?? []),
    ...(joined.match(ghsaPattern) ?? []),
  ])).map((id) => id.toUpperCase());

  const versionMatches = Array.from(title.matchAll(/(?:before|prior to|<)\s*v?(\d+\.\d+(?:\.\d+)?)/gi))
    .concat(Array.from(joined.matchAll(/(?:before|prior to|<)\s*v?(\d+\.\d+(?:\.\d+)?)/gi)));
  const affectedVersions = Array.from(new Set(versionMatches.map((match) => match[1])));

  const riskExplanation = inferredVulnerabilities.length > 0
    ? `Commit references ${inferredVulnerabilities.join(', ')}, which strongly suggests a direct security remediation.`
    : 'No explicit CVE/GHSA identifiers were found. Classification is inferred from commit message wording and touched files.';

  return {
    commitHash: fullHash,
    title,
    filesChanged,
    inferredVulnerabilities,
    affectedVersions,
    riskExplanation,
  };
}
