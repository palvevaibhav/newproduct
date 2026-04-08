import { describe, expect, it } from 'vitest';
import { computeRiskScore, correlateVersion, NormalizedVulnRecord } from './securityIntelligence';

const makeVuln = (overrides: Partial<NormalizedVulnRecord> = {}): NormalizedVulnRecord => ({
  id: 'OSV-1',
  aliases: ['CVE-2026-1000'],
  source: 'OSV',
  packageName: 'express',
  ecosystem: 'npm',
  summary: 'Prototype pollution',
  details: 'Details',
  severity: 'HIGH',
  cvssScore: 7.8,
  introducedVersions: ['0'],
  fixedVersions: ['4.19.0'],
  references: ['https://github.com/expressjs/express/commit/abc'],
  ...overrides,
});

describe('securityIntelligence', () => {
  it('correlates vulnerable versions when current version is below fixed version', () => {
    const result = correlateVersion('express', '4.18.2', [makeVuln()]);

    expect(result.vulnerable).toBe(true);
    expect(result.matchedVulnerabilities).toHaveLength(1);
    expect(result.matchedVulnerabilities[0].id).toBe('OSV-1');
  });

  it('does not flag vulnerability when package version is already fixed', () => {
    const result = correlateVersion('express', '4.19.1', [makeVuln()]);

    expect(result.vulnerable).toBe(false);
    expect(result.matchedVulnerabilities).toHaveLength(0);
  });

  it('computes elevated risk score without patch references', () => {
    const score = computeRiskScore([
      makeVuln({ id: 'OSV-2', severity: 'CRITICAL', cvssScore: 9.8, references: [] }),
      makeVuln({ id: 'OSV-3', severity: 'HIGH', cvssScore: 8.1, references: [] }),
    ], false);

    expect(score.level).toBe('CRITICAL');
    expect(score.score).toBeGreaterThanOrEqual(80);
    expect(score.rationale).toHaveLength(3);
  });
});
