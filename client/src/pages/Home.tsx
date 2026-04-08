import { useAuth } from "@/_core/hooks/useAuth";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Loader2, Search, AlertTriangle, CheckCircle, Clock, Shield } from "lucide-react";
import { getLoginUrl } from "@/const";
import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { Streamdown } from 'streamdown';

export default function Home() {
  const { user, loading: authLoading, isAuthenticated } = useAuth();
  const [query, setQuery] = useState('');
  const [isSearching, setIsSearching] = useState(false);
  const [lastResult, setLastResult] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);

  const securityQuery = trpc.security.query.useMutation();
  const recentQueries = trpc.security.recentQueries.useQuery(5, {
    enabled: isAuthenticated && !authLoading,
  });

  const handleSearch = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!query.trim()) return;

    setIsSearching(true);
    setError(null);

    try {
      const result = await securityQuery.mutateAsync(query);
      if (result.success && result.data) {
        setLastResult(result.data);
      } else {
        setError(result.error || 'Failed to process query');
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred');
    } finally {
      setIsSearching(false);
    }
  };

  if (authLoading) {
    return (
      <div className="min-h-screen bg-[#0a1628] flex items-center justify-center">
        <Loader2 className="animate-spin text-white" size={40} />
      </div>
    );
  }

  if (!isAuthenticated) {
    return (
      <div className="min-h-screen bg-[#0a1628] relative overflow-hidden">
        <div className="absolute inset-0 opacity-5">
          <svg width="100%" height="100%" xmlns="http://www.w3.org/2000/svg">
            <defs>
              <pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse">
                <path d="M 40 0 L 0 0 0 40" fill="none" stroke="white" strokeWidth="0.5" />
              </pattern>
            </defs>
            <rect width="100%" height="100%" fill="url(#grid)" />
          </svg>
        </div>

        <div className="relative z-10 flex flex-col items-center justify-center min-h-screen px-4">
          <div className="max-w-2xl text-center">
            <div className="mb-8 flex justify-center">
              <Shield className="text-white" size={64} />
            </div>
            <h1 className="text-5xl font-bold text-white mb-4">Decision RAG</h1>
            <p className="text-xl text-white/70 mb-8">Security Intelligence Platform</p>
            <p className="text-white/60 mb-12 max-w-xl mx-auto">
              Query CVEs, analyze package vulnerabilities, and get AI-powered security insights powered by multi-source data integration.
            </p>
            <a href={getLoginUrl()}>
              <Button className="bg-white text-[#0a1628] hover:bg-white/90 px-8 py-6 text-lg">
                Sign In to Continue
              </Button>
            </a>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#0a1628] relative overflow-hidden">
      <div className="absolute inset-0 opacity-5 pointer-events-none">
        <svg width="100%" height="100%" xmlns="http://www.w3.org/2000/svg">
          <defs>
            <pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse">
              <path d="M 40 0 L 0 0 0 40" fill="none" stroke="white" strokeWidth="0.5" />
            </pattern>
          </defs>
          <rect width="100%" height="100%" fill="url(#grid)" />
        </svg>
      </div>

      <div className="relative z-10">
        <div className="border-b border-white/10 bg-[#0a1628]/80 backdrop-blur">
          <div className="max-w-7xl mx-auto px-6 py-6 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Shield className="text-white" size={32} />
              <h1 className="text-2xl font-bold text-white">Decision RAG</h1>
            </div>
            <div className="text-white/60 text-sm">Welcome, {user?.name || 'User'}</div>
          </div>
        </div>

        <div className="max-w-7xl mx-auto px-6 py-12">
          <div className="mb-12">
            <form onSubmit={handleSearch} className="mb-6">
              <div className="relative">
                <Input
                  type="text"
                  placeholder="Enter CVE ID, package name, version, or security question..."
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  className="w-full bg-white/5 border border-white/20 text-white placeholder:text-white/40 py-3 px-4 rounded-lg focus:border-white/40 focus:bg-white/10"
                  disabled={isSearching}
                />
                <Button
                  type="submit"
                  disabled={isSearching || !query.trim()}
                  className="absolute right-2 top-1/2 -translate-y-1/2 bg-white text-[#0a1628] hover:bg-white/90"
                >
                  {isSearching ? <Loader2 className="animate-spin" size={20} /> : <Search size={20} />}
                </Button>
              </div>
            </form>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              <button
                onClick={() => setQuery('CVE-2024-1234')}
                className="text-left p-3 bg-white/5 border border-white/10 rounded-lg hover:bg-white/10 hover:border-white/20 transition text-white/70 text-sm"
              >
                <span className="font-mono">CVE-2024-1234</span>
              </button>
              <button
                onClick={() => setQuery('Is React 18.2.0 safe from XSS?')}
                className="text-left p-3 bg-white/5 border border-white/10 rounded-lg hover:bg-white/10 hover:border-white/20 transition text-white/70 text-sm"
              >
                <span>Is React 18.2.0 safe from XSS?</span>
              </button>
              <a
                href="/dashboard"
                className="text-left p-3 bg-white/5 border border-white/10 rounded-lg hover:bg-white/10 hover:border-white/20 transition text-white/70 text-sm flex items-center justify-center font-semibold"
              >
                <span>View Dashboard →</span>
              </a>
            </div>
          </div>

          {error && (
            <Card className="mb-8 bg-red-500/10 border border-red-500/30 p-4">
              <div className="flex gap-3">
                <AlertTriangle className="text-red-400 flex-shrink-0" size={20} />
                <div className="text-red-200">{error}</div>
              </div>
            </Card>
          )}

          {lastResult && (
            <div className="mb-12 space-y-6">
              <div className="border-t border-white/10 pt-8">
                <h2 className="text-2xl font-bold text-white mb-6">Analysis Results</h2>

                <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
                  <Card className="bg-white/5 border border-white/10 p-4">
                    <div className="text-white/60 text-sm mb-2">Risk Level</div>
                    <div className={`text-2xl font-bold ${
                      lastResult.synthesis.riskLevel === 'CRITICAL' ? 'text-red-400' :
                      lastResult.synthesis.riskLevel === 'HIGH' ? 'text-orange-400' :
                      lastResult.synthesis.riskLevel === 'MEDIUM' ? 'text-yellow-400' :
                      'text-green-400'
                    }`}>
                      {lastResult.synthesis.riskLevel}
                    </div>
                  </Card>

                  <Card className="bg-white/5 border border-white/10 p-4">
                    <div className="text-white/60 text-sm mb-2">CVSS Score</div>
                    <div className="text-2xl font-bold text-white">
                      {lastResult.synthesis.cvssScore ? lastResult.synthesis.cvssScore.toFixed(1) : 'N/A'}
                    </div>
                  </Card>

                  <Card className="bg-white/5 border border-white/10 p-4">
                    <div className="text-white/60 text-sm mb-2">Affected Versions</div>
                    <div className="text-lg font-mono text-white">
                      {lastResult.synthesis.affectedVersions.length}
                    </div>
                  </Card>

                  <Card className="bg-white/5 border border-white/10 p-4">
                    <div className="text-white/60 text-sm mb-2">Fixed Versions</div>
                    <div className="text-lg font-mono text-white">
                      {lastResult.synthesis.fixedVersions.length}
                    </div>
                  </Card>
                </div>

                <Card className="bg-white/5 border border-white/10 p-6 mb-6">
                  <h3 className="text-lg font-bold text-white mb-4">Summary</h3>
                  <Streamdown className="text-white/80 text-sm leading-relaxed">
                    {lastResult.synthesis.summary}
                  </Streamdown>
                </Card>

                {lastResult.synthesis.recommendations.length > 0 && (
                  <Card className="bg-white/5 border border-white/10 p-6 mb-6">
                    <h3 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
                      <CheckCircle size={20} className="text-green-400" />
                      Recommendations
                    </h3>
                    <ul className="space-y-2">
                      {lastResult.synthesis.recommendations.map((rec: string, i: number) => (
                        <li key={i} className="text-white/80 text-sm flex gap-2">
                          <span className="text-white/40">•</span>
                          <span>{rec}</span>
                        </li>
                      ))}
                    </ul>
                  </Card>
                )}

                {lastResult.synthesis.fixedVersions.length > 0 && (
                  <Card className="bg-white/5 border border-white/10 p-6 mb-6">
                    <h3 className="text-lg font-bold text-white mb-4">Fixed Versions</h3>
                    <div className="flex flex-wrap gap-2">
                      {lastResult.synthesis.fixedVersions.map((version: string, i: number) => (
                        <span key={i} className="px-3 py-1 bg-green-500/20 border border-green-500/30 text-green-300 rounded text-sm font-mono">
                          {version}
                        </span>
                      ))}
                    </div>
                  </Card>
                )}
              </div>
            </div>
          )}

          {recentQueries.data && recentQueries.data.length > 0 && !lastResult && (
            <div>
              <h2 className="text-xl font-bold text-white mb-4 flex items-center gap-2">
                <Clock size={20} />
                Recent Queries
              </h2>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                {recentQueries.data.map((q: any) => (
                  <Card
                    key={q.id}
                    className="bg-white/5 border border-white/10 p-4 cursor-pointer hover:bg-white/10 hover:border-white/20 transition"
                    onClick={() => setQuery(q.queryText)}
                  >
                    <div className="text-white/60 text-xs mb-2">{new Date(q.queriedAt).toLocaleDateString()}</div>
                    <div className="text-white font-mono text-sm truncate">{q.queryText}</div>
                  </Card>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
