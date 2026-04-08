import { describe, expect, it, vi } from 'vitest';
import { buildCveIntelReport } from './securityIntelligence';
import { fetchFromAllSources } from './dataFetchers';

vi.mock('./dataFetchers', async () => {
  const actual = await vi.importActual<typeof import('./dataFetchers')>('./dataFetchers');
  return {
    ...actual,
    fetchFromAllSources: vi.fn(),
  };
});

const mockedFetchFromAllSources = vi.mocked(fetchFromAllSources);

describe('buildCveIntelReport', () => {
  it('normalizes and merges NVD and OSV records for a CVE', async () => {
    mockedFetchFromAllSources.mockResolvedValue({
      allResults: [],
      successfulResults: [{ source: 'NVD', success: true, data: {}, timestamp: new Date() }],
      hasData: true,
      aggregatedData: {
        nvd: {
          cve: {
            id: 'CVE-2021-3587',
            published: '2021-06-28T11:15:00.000',
            descriptions: [{ lang: 'en', value: 'A test vulnerability' }],
            references: [{ url: 'https://nvd.nist.gov/vuln/detail/CVE-2021-3587' }],
            metrics: {
              cvssMetricV31: [
                {
                  cvssData: {
                    baseScore: 8.8,
                  },
                },
              ],
            },
          },
        },
        osv: [
          {
            id: 'GHSA-1111-2222-3333',
            aliases: ['CVE-2021-3587'],
            summary: 'OSV summary',
            details: 'OSV details',
            severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H 9.8' }],
            references: [{ url: 'https://github.com/example/repo/commit/abcd' }],
          },
        ],
      },
    });

    const report = await buildCveIntelReport('cve-2021-3587');

    expect(report.cveId).toBe('CVE-2021-3587');
    expect(report.found).toBe(true);
    expect(report.records).toHaveLength(1);
    expect(report.records[0].sources).toContain('NVD');
    expect(report.records[0].sources).toContain('OSV');
    expect(report.riskScore.level).toBe('CRITICAL');
  });

  it('rejects invalid CVE IDs', async () => {
    await expect(buildCveIntelReport('invalid-cve')).rejects.toThrow('Invalid CVE ID format');
  });
});
