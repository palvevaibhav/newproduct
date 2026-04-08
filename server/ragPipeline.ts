/**
 * RAG Pipeline: Retrieval-Augmented Generation for security intelligence
 * Retrieves data from multiple sources and synthesizes comprehensive answers using LLM
 */

import { invokeLLM } from './_core/llm';
import { aggregateResults, fetchFromAllSources, FetcherResult } from './dataFetchers';
import { ClassificationResult, extractEntitiesByType } from './queryClassifier';

export interface RAGResult {
  query: string;
  classification: ClassificationResult;
  sourceResults: ReturnType<typeof aggregateResults>;
  synthesis: {
    summary: string;
    riskLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';
    cvssScore: number | null;
    affectedVersions: string[];
    fixedVersions: string[];
    recommendations: string[];
    references: Array<{ title: string; url: string }>;
  };
  timestamp: Date;
}

/**
 * Extract CVSS score from aggregated vulnerability data
 */
function extractCVSSScore(data: Record<string, unknown>): number | null {
  // Try NVD format
  if (data.nvd) {
    const nvdData = data.nvd as Record<string, unknown>;
    if (nvdData.cvssMetrics && Array.isArray(nvdData.cvssMetrics)) {
      const metrics = nvdData.cvssMetrics as Array<Record<string, unknown>>;
      for (const metric of metrics) {
        if (metric.cvssData && typeof metric.cvssData === 'object') {
          const cvssData = metric.cvssData as Record<string, unknown>;
          if (typeof cvssData.baseScore === 'number') {
            return cvssData.baseScore;
          }
        }
      }
    }
  }

  // Try GHSA format
  if (data.ghsa) {
    const ghsaData = data.ghsa as Record<string, unknown>;
    if (typeof ghsaData.cvss === 'object' && ghsaData.cvss !== null) {
      const cvss = ghsaData.cvss as Record<string, unknown>;
      if (typeof cvss.score === 'number') {
        return cvss.score;
      }
    }
  }

  // Try OSV format
  if (data.osv) {
    const osvData = data.osv as Record<string, unknown>;
    if (Array.isArray(osvData)) {
      const firstVuln = osvData[0] as Record<string, unknown>;
      if (firstVuln.severity && typeof firstVuln.severity === 'string') {
        const severityMap: Record<string, number> = {
          'CRITICAL': 9.0,
          'HIGH': 7.5,
          'MEDIUM': 5.0,
          'LOW': 2.5,
        };
        return severityMap[firstVuln.severity] || null;
      }
    }
  }

  return null;
}

/**
 * Determine risk level based on CVSS score
 */
function determineRiskLevel(cvssScore: number | null): RAGResult['synthesis']['riskLevel'] {
  if (cvssScore === null) return 'UNKNOWN';
  if (cvssScore >= 9.0) return 'CRITICAL';
  if (cvssScore >= 7.0) return 'HIGH';
  if (cvssScore >= 4.0) return 'MEDIUM';
  return 'LOW';
}

/**
 * Extract affected and fixed versions from aggregated data
 */
function extractVersions(data: Record<string, unknown>): {
  affectedVersions: string[];
  fixedVersions: string[];
} {
  const affectedVersions = new Set<string>();
  const fixedVersions = new Set<string>();

  // Extract from NVD
  if (data.nvd && typeof data.nvd === 'object') {
    const nvdData = data.nvd as Record<string, unknown>;
    if (nvdData.configurations && Array.isArray(nvdData.configurations)) {
      const configs = nvdData.configurations as Array<Record<string, unknown>>;
      for (const config of configs) {
        if (config.nodes && Array.isArray(config.nodes)) {
          const nodes = config.nodes as Array<Record<string, unknown>>;
          for (const node of nodes) {
            if (node.cpeMatch && Array.isArray(node.cpeMatch)) {
              const matches = node.cpeMatch as Array<Record<string, unknown>>;
              for (const match of matches) {
                if (match.versionStartIncluding && typeof match.versionStartIncluding === 'string') {
                  affectedVersions.add(match.versionStartIncluding as string);
                }
                if (match.versionEndExcluding && typeof match.versionEndExcluding === 'string') {
                  fixedVersions.add(match.versionEndExcluding as string);
                }
              }
            }
          }
        }
      }
    }
  }

  // Extract from OSV
  if (data.osv && Array.isArray(data.osv)) {
    const osvList = data.osv as Array<Record<string, unknown>>;
    for (const vuln of osvList) {
      if (vuln.affected && Array.isArray(vuln.affected)) {
        const affected = vuln.affected as Array<Record<string, unknown>>;
        for (const pkg of affected) {
          if (pkg.ranges && Array.isArray(pkg.ranges)) {
            const ranges = pkg.ranges as Array<Record<string, unknown>>;
            for (const range of ranges) {
              if (range.events && Array.isArray(range.events)) {
                const events = range.events as Array<Record<string, unknown>>;
                for (const event of events) {
                  if (event.introduced && typeof event.introduced === 'string') {
                    affectedVersions.add(event.introduced as string);
                  }
                  if (event.fixed && typeof event.fixed === 'string') {
                    fixedVersions.add(event.fixed as string);
                  }
                }
              }
            }
          }
        }
      }
    }
  }

  return {
    affectedVersions: Array.from(affectedVersions),
    fixedVersions: Array.from(fixedVersions),
  };
}

/**
 * Extract references from aggregated data
 */
function extractReferences(data: Record<string, unknown>): Array<{ title: string; url: string }> {
  const references: Array<{ title: string; url: string }> = [];
  const seenUrls = new Set<string>();

  // Extract from NVD
  if (data.nvd && typeof data.nvd === 'object') {
    const nvdData = data.nvd as Record<string, unknown>;
    if (nvdData.references && Array.isArray(nvdData.references)) {
      const refs = nvdData.references as Array<Record<string, unknown>>;
      for (const ref of refs) {
        if (typeof ref.url === 'string' && !seenUrls.has(ref.url)) {
          seenUrls.add(ref.url);
          references.push({
            title: typeof ref.source === 'string' ? ref.source : 'Reference',
            url: ref.url,
          });
        }
      }
    }
  }

  // Extract from GHSA
  if (data.ghsa && Array.isArray(data.ghsa)) {
    const ghsaList = data.ghsa as Array<Record<string, unknown>>;
    for (const advisory of ghsaList) {
      if (advisory.references && Array.isArray(advisory.references)) {
        const refs = advisory.references as Array<Record<string, unknown>>;
        for (const ref of refs) {
          if (typeof ref.url === 'string' && !seenUrls.has(ref.url)) {
            seenUrls.add(ref.url);
            references.push({
              title: 'GitHub Advisory Reference',
              url: ref.url,
            });
          }
        }
      }
    }
  }

  return references.slice(0, 5); // Limit to 5 references
}

/**
 * Generate LLM synthesis of vulnerability data
 */
async function generateSynthesis(
  query: string,
  classification: ClassificationResult,
  aggregatedData: Record<string, unknown>,
  cvssScore: number | null,
  affectedVersions: string[],
  fixedVersions: string[]
): Promise<string> {
  const entities = extractEntitiesByType(classification, 'cve');
  const packages = extractEntitiesByType(classification, 'package');
  const vulnTypes = extractEntitiesByType(classification, 'vulnerability_type');

  const systemPrompt = `You are a security expert analyzing vulnerability data. Provide a clear, concise summary of the security vulnerability or package risk assessment. Focus on:
1. What the vulnerability is
2. Who is affected
3. Risk level and CVSS score
4. Recommended actions
5. Affected and fixed versions

Keep the response under 500 words and use technical but accessible language.`;

  const userPrompt = `Analyze this security query and provide a comprehensive summary:

Query: "${query}"
Query Type: ${classification.queryType}
Detected Entities:
- CVE IDs: ${entities.length > 0 ? entities.join(', ') : 'None'}
- Packages: ${packages.length > 0 ? packages.join(', ') : 'None'}
- Vulnerability Types: ${vulnTypes.length > 0 ? vulnTypes.join(', ') : 'None'}

Vulnerability Data:
${JSON.stringify(aggregatedData, null, 2).slice(0, 2000)}

CVSS Score: ${cvssScore !== null ? cvssScore : 'Not available'}
Affected Versions: ${affectedVersions.length > 0 ? affectedVersions.join(', ') : 'Not specified'}
Fixed Versions: ${fixedVersions.length > 0 ? fixedVersions.join(', ') : 'Not available'}

Please provide a comprehensive security analysis based on this data.`;

  try {
    const response = await invokeLLM({
      messages: [
        { role: 'system', content: systemPrompt },
        { role: 'user', content: userPrompt },
      ],
    });

    if (response.choices && response.choices[0] && response.choices[0].message) {
      const message = response.choices[0].message;
      if (typeof message.content === 'string') {
        return message.content;
      }
    }
  } catch (error) {
    console.error('LLM synthesis error:', error);
  }

  // Fallback synthesis if LLM fails
  return `Security Analysis for ${query}:\n\nThis query relates to ${classification.queryType} vulnerabilities. Based on the available data, the risk level is ${determineRiskLevel(cvssScore)}. ${fixedVersions.length > 0 ? `Updates are available: ${fixedVersions.join(', ')}` : 'Please check official security advisories for patches.'}`;
}

/**
 * Run the complete RAG pipeline
 */
export async function runRAGPipeline(
  query: string,
  classification: ClassificationResult,
  options?: {
    nvdApiKey?: string;
    githubToken?: string;
  }
): Promise<RAGResult> {
  const startTime = Date.now();

  // Fetch data from all sources
  const sourceResults = await fetchFromAllSources(
    classification.primaryEntity?.value || query,
    (classification.queryType === 'natural_language' ? 'package' : classification.queryType) as any,
    options
  );

  // Extract key information
  const cvssScore = extractCVSSScore(sourceResults.aggregatedData);
  const { affectedVersions, fixedVersions } = extractVersions(sourceResults.aggregatedData);
  const references = extractReferences(sourceResults.aggregatedData);
  const riskLevel = determineRiskLevel(cvssScore);

  // Generate LLM synthesis
  const summary = await generateSynthesis(
    query,
    classification,
    sourceResults.aggregatedData,
    cvssScore,
    affectedVersions,
    fixedVersions
  );

  // Generate recommendations based on risk level
  const recommendations: string[] = [];
  if (riskLevel === 'CRITICAL') {
    recommendations.push('Apply security patch immediately');
    recommendations.push('Review affected systems for exploitation');
    recommendations.push('Monitor for suspicious activity');
  } else if (riskLevel === 'HIGH') {
    recommendations.push('Plan patch deployment within 1-2 weeks');
    recommendations.push('Assess impact on your systems');
    recommendations.push('Consider temporary mitigations if available');
  } else if (riskLevel === 'MEDIUM') {
    recommendations.push('Schedule patch deployment within 1 month');
    recommendations.push('Monitor for exploit availability');
  } else {
    recommendations.push('Monitor for updates');
    recommendations.push('Apply patches during regular maintenance windows');
  }

  if (fixedVersions.length > 0) {
    recommendations.push(`Update to version ${fixedVersions[0]} or later`);
  }

  return {
    query,
    classification,
    sourceResults,
    synthesis: {
      summary,
      riskLevel,
      cvssScore,
      affectedVersions,
      fixedVersions,
      recommendations,
      references,
    },
    timestamp: new Date(),
  };
}
