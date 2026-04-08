/**
 * Data Fetchers: Retrieve vulnerability data from multiple sources
 * Supports: NVD, OSV, GHSA, NPM, Red Hat
 */

import axios from 'axios';

const httpClient = axios.create({
  timeout: 20_000,
  headers: {
    'User-Agent': 'decision-rag-security/1.0 (+security-research)',
    'Accept': 'application/json',
  },
});

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export interface FetcherResult {
  source: string;
  success: boolean;
  data: unknown;
  error?: string;
  timestamp: Date;
}

/**
 * Fetch CVE data from NVD (National Vulnerability Database)
 */
export async function fetchFromNVD(cveId: string, apiKey?: string): Promise<FetcherResult> {
  try {
    const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cveId}`;
    const headers = apiKey ? { 'apiKey': apiKey } : {};
    
    const response = await httpClient.get(url, { headers });
    
    if (response.status === 200 && response.data?.vulnerabilities) {
      return {
        source: 'NVD',
        success: true,
        data: response.data.vulnerabilities[0] || null,
        timestamp: new Date(),
      };
    }
    
    return {
      source: 'NVD',
      success: false,
      data: null,
      error: `HTTP ${response.status}`,
      timestamp: new Date(),
    };
  } catch (error) {
    return {
      source: 'NVD',
      success: false,
      data: null,
      error: error instanceof Error ? error.message : 'Unknown error',
      timestamp: new Date(),
    };
  }
}

/**
 * Fetch vulnerability data from OSV (Open Source Vulnerabilities)
 */
export async function fetchFromOSV(query: string, queryType: 'cve' | 'package'): Promise<FetcherResult> {
  try {
    const url = 'https://api.osv.dev/v1/query';
    const payload = queryType === 'cve'
      ? { cve: query }
      : { package: { name: query } };
    
    const response = await httpClient.post(url, payload);
    
    if (response.status === 200) {
      return {
        source: 'OSV',
        success: true,
        data: response.data.vulns || [],
        timestamp: new Date(),
      };
    }
    
    return {
      source: 'OSV',
      success: false,
      data: null,
      error: `HTTP ${response.status}`,
      timestamp: new Date(),
    };
  } catch (error) {
    return {
      source: 'OSV',
      success: false,
      data: null,
      error: error instanceof Error ? error.message : 'Unknown error',
      timestamp: new Date(),
    };
  }
}

/**
 * Fetch GitHub Security Advisory data
 */
export async function fetchFromGHSA(query: string, githubToken?: string): Promise<FetcherResult> {
  try {
    const isGHSAId = /^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$/i.test(query);
    const isCVEId = /^CVE-\d{4}-\d{4,}$/i.test(query);
    
    const url = isGHSAId
      ? `https://api.github.com/advisories/${query.toUpperCase()}`
      : isCVEId
      ? `https://api.github.com/advisories?cve_id=${query}&per_page=1`
      : `https://api.github.com/advisories?query=${encodeURIComponent(query)}&per_page=5`;
    
    const headers = githubToken ? { 'Authorization': `Bearer ${githubToken}` } : {};
    
    const response = await httpClient.get(url, { headers });
    
    if (response.status === 200) {
      const data = Array.isArray(response.data) ? response.data : [response.data];
      return {
        source: 'GHSA',
        success: true,
        data: data.filter(Boolean),
        timestamp: new Date(),
      };
    }
    
    return {
      source: 'GHSA',
      success: false,
      data: null,
      error: `HTTP ${response.status}`,
      timestamp: new Date(),
    };
  } catch (error) {
    return {
      source: 'GHSA',
      success: false,
      data: null,
      error: error instanceof Error ? error.message : 'Unknown error',
      timestamp: new Date(),
    };
  }
}

/**
 * Fetch NPM security advisory data
 */
export async function fetchFromNPM(packageName: string): Promise<FetcherResult> {
  try {
    // Try NPM registry API first
    const registryUrl = `https://registry.npmjs.org/-/npm/v1/security/advisories/search?package=${encodeURIComponent(packageName)}`;
    
    const response = await httpClient.get(registryUrl);
    
    if (response.status === 200) {
      return {
        source: 'NPM',
        success: true,
        data: response.data,
        timestamp: new Date(),
      };
    }
    
    return {
      source: 'NPM',
      success: false,
      data: null,
      error: `HTTP ${response.status}`,
      timestamp: new Date(),
    };
  } catch (error) {
    return {
      source: 'NPM',
      success: false,
      data: null,
      error: error instanceof Error ? error.message : 'Unknown error',
      timestamp: new Date(),
    };
  }
}

/**
 * Fetch Red Hat security data
 */
export async function fetchFromRedHat(cveId: string): Promise<FetcherResult> {
  try {
    if (!/^CVE-\d{4}-\d{4,}$/i.test(cveId)) {
      return {
        source: 'RedHat',
        success: false,
        data: null,
        error: 'Invalid CVE ID format',
        timestamp: new Date(),
      };
    }
    
    const url = `https://access.redhat.com/hydra/rest/securitydata/cve/${cveId}.json`;
    
    const response = await httpClient.get(url);
    
    if (response.status === 200) {
      return {
        source: 'RedHat',
        success: true,
        data: response.data,
        timestamp: new Date(),
      };
    }
    
    return {
      source: 'RedHat',
      success: false,
      data: null,
      error: `HTTP ${response.status}`,
      timestamp: new Date(),
    };
  } catch (error) {
    return {
      source: 'RedHat',
      success: false,
      data: null,
      error: error instanceof Error ? error.message : 'Unknown error',
      timestamp: new Date(),
    };
  }
}

/**
 * Aggregate results from multiple sources
 */
export function aggregateResults(results: FetcherResult[]): {
  allResults: FetcherResult[];
  successfulResults: FetcherResult[];
  hasData: boolean;
  aggregatedData: Record<string, unknown>;
} {
  const successfulResults = results.filter((r) => r.success && r.data);
  const aggregatedData: Record<string, unknown> = {};
  
  for (const result of successfulResults) {
    aggregatedData[result.source.toLowerCase()] = result.data;
  }
  
  return {
    allResults: results,
    successfulResults,
    hasData: successfulResults.length > 0,
    aggregatedData,
  };
}

/**
 * Fetch data from all available sources for a given query
 */
export async function fetchFromAllSources(
  query: string,
  queryType: 'cve' | 'ghsa' | 'package' | 'vulnerability_type',
  options?: {
    nvdApiKey?: string;
    githubToken?: string;
  }
): Promise<ReturnType<typeof aggregateResults>> {
  const results: FetcherResult[] = [];
  
  // Add small delays between requests to avoid rate limiting
  if (queryType === 'cve' || queryType === 'vulnerability_type') {
    results.push(await fetchFromNVD(query, options?.nvdApiKey));
    await sleep(500);
    results.push(await fetchFromOSV(query, 'cve'));
    await sleep(500);
    results.push(await fetchFromGHSA(query, options?.githubToken));
    await sleep(500);
    results.push(await fetchFromRedHat(query));
  }
  
  if (queryType === 'package') {
    results.push(await fetchFromOSV(query, 'package'));
    await sleep(500);
    results.push(await fetchFromNPM(query));
    await sleep(500);
    results.push(await fetchFromGHSA(query, options?.githubToken));
  }
  
  if (queryType === 'ghsa') {
    results.push(await fetchFromGHSA(query, options?.githubToken));
    await sleep(500);
    results.push(await fetchFromOSV(query, 'cve'));
  }
  
  return aggregateResults(results);
}
