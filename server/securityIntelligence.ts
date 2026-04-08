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
