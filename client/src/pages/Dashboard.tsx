import { useAuth } from "@/_core/hooks/useAuth";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Loader2, TrendingUp, AlertTriangle, CheckCircle, Package } from "lucide-react";
import { useState } from "react";
import { trpc } from "@/lib/trpc";
import {
  LineChart,
  Line,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
} from "recharts";

export default function Dashboard() {
  const { user, loading: authLoading, isAuthenticated } = useAuth();
  const [selectedDays, setSelectedDays] = useState(30);

  const dashboardOverview = trpc.dashboard.overview.useQuery(undefined, {
    enabled: isAuthenticated && !authLoading,
  });

  const vulnerabilityTrend = trpc.dashboard.vulnerabilityTrend.useQuery(
    { days: selectedDays },
    {
      enabled: isAuthenticated && !authLoading,
    }
  );

  const activeVulnerabilities = trpc.dashboard.activeVulnerabilities.useQuery(undefined, {
    enabled: isAuthenticated && !authLoading,
  });

  if (authLoading) {
    return (
      <div className="min-h-screen bg-[#0a1628] flex items-center justify-center">
        <Loader2 className="animate-spin text-white" size={40} />
      </div>
    );
  }

  if (!isAuthenticated) {
    return null;
  }

  const overview = dashboardOverview.data;
  const trendData = vulnerabilityTrend.data || [];
  const activeVulns = activeVulnerabilities.data || [];

  // Prepare pie chart data for severity distribution
  const severityData = overview?.severityDistribution
    ? [
        { name: "CRITICAL", value: overview.severityDistribution.CRITICAL, color: "#ef4444" },
        { name: "HIGH", value: overview.severityDistribution.HIGH, color: "#f97316" },
        { name: "MEDIUM", value: overview.severityDistribution.MEDIUM, color: "#eab308" },
        { name: "LOW", value: overview.severityDistribution.LOW, color: "#22c55e" },
      ]
    : [];

  // Prepare package health heatmap data
  const packageHealthData = overview?.packageHealthScores || [];

  return (
    <div className="min-h-screen bg-[#0a1628] relative overflow-hidden">
      {/* Blueprint grid background */}
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
        {/* Header */}
        <div className="border-b border-white/10 bg-[#0a1628]/80 backdrop-blur">
          <div className="max-w-7xl mx-auto px-6 py-6">
            <h1 className="text-3xl font-bold text-white">Security Dashboard</h1>
            <p className="text-white/60 mt-2">Monitor security status of all packages over time</p>
          </div>
        </div>

        {/* Main content */}
        <div className="max-w-7xl mx-auto px-6 py-12">
          {/* KPI Cards */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
            <Card className="bg-white/5 border border-white/10 p-6">
              <div className="text-white/60 text-sm mb-2 flex items-center gap-2">
                <Package size={16} />
                Monitored Packages
              </div>
              <div className="text-3xl font-bold text-white">
                {overview?.snapshot?.totalMonitoredPackages || 0}
              </div>
            </Card>

            <Card className="bg-white/5 border border-white/10 p-6">
              <div className="text-white/60 text-sm mb-2 flex items-center gap-2">
                <AlertTriangle size={16} className="text-red-400" />
                Total Vulnerabilities
              </div>
              <div className="text-3xl font-bold text-red-400">
                {overview?.snapshot?.totalVulnerabilities || 0}
              </div>
            </Card>

            <Card className="bg-white/5 border border-white/10 p-6">
              <div className="text-white/60 text-sm mb-2 flex items-center gap-2">
                <TrendingUp size={16} className="text-blue-400" />
                Overall Risk Level
              </div>
              <div className={`text-2xl font-bold ${
                overview?.snapshot?.overallRiskLevel === 'CRITICAL' ? 'text-red-400' :
                overview?.snapshot?.overallRiskLevel === 'HIGH' ? 'text-orange-400' :
                overview?.snapshot?.overallRiskLevel === 'MEDIUM' ? 'text-yellow-400' :
                'text-green-400'
              }`}>
                {overview?.snapshot?.overallRiskLevel || 'UNKNOWN'}
              </div>
            </Card>

            <Card className="bg-white/5 border border-white/10 p-6">
              <div className="text-white/60 text-sm mb-2 flex items-center gap-2">
                <CheckCircle size={16} className="text-green-400" />
                Avg Health Score
              </div>
              <div className="text-3xl font-bold text-green-400">
                {overview?.snapshot?.averageHealthScore || 0}/100
              </div>
            </Card>
          </div>

          {/* Charts Section */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
            {/* Vulnerability Trend */}
            <Card className="lg:col-span-2 bg-white/5 border border-white/10 p-6">
              <div className="mb-4 flex items-center justify-between">
                <h3 className="text-lg font-bold text-white">Vulnerability Trend</h3>
                <div className="flex gap-2">
                  {[7, 30, 90].map((days) => (
                    <Button
                      key={days}
                      variant={selectedDays === days ? "default" : "outline"}
                      size="sm"
                      onClick={() => setSelectedDays(days)}
                      className={selectedDays === days ? "bg-white text-[#0a1628]" : "border-white/20 text-white/70"}
                    >
                      {days}d
                    </Button>
                  ))}
                </div>
              </div>
              {trendData.length > 0 ? (
                <ResponsiveContainer width="100%" height={300}>
                  <LineChart data={trendData}>
                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.1)" />
                    <XAxis
                      dataKey="snapshotDate"
                      stroke="rgba(255,255,255,0.5)"
                      tick={{ fontSize: 12 }}
                    />
                    <YAxis stroke="rgba(255,255,255,0.5)" tick={{ fontSize: 12 }} />
                    <Tooltip
                      contentStyle={{ backgroundColor: "rgba(10,22,40,0.9)", border: "1px solid rgba(255,255,255,0.2)" }}
                      labelStyle={{ color: "white" }}
                    />
                    <Legend />
                    <Line
                      type="monotone"
                      dataKey="totalVulnerabilities"
                      stroke="#ef4444"
                      name="Total Vulnerabilities"
                    />
                    <Line
                      type="monotone"
                      dataKey="packagesWithCritical"
                      stroke="#f97316"
                      name="Critical Packages"
                    />
                  </LineChart>
                </ResponsiveContainer>
              ) : (
                <div className="h-[300px] flex items-center justify-center text-white/40">
                  No trend data available
                </div>
              )}
            </Card>

            {/* Severity Distribution */}
            <Card className="bg-white/5 border border-white/10 p-6">
              <h3 className="text-lg font-bold text-white mb-4">Severity Distribution</h3>
              {severityData.some((d) => d.value > 0) ? (
                <ResponsiveContainer width="100%" height={300}>
                  <PieChart>
                    <Pie
                      data={severityData}
                      cx="50%"
                      cy="50%"
                      labelLine={false}
                      label={({ name, value }) => `${name}: ${value}`}
                      outerRadius={80}
                      fill="#8884d8"
                      dataKey="value"
                    >
                      {severityData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Pie>
                    <Tooltip
                      contentStyle={{ backgroundColor: "rgba(10,22,40,0.9)", border: "1px solid rgba(255,255,255,0.2)" }}
                      labelStyle={{ color: "white" }}
                    />
                  </PieChart>
                </ResponsiveContainer>
              ) : (
                <div className="h-[300px] flex items-center justify-center text-white/40">
                  No vulnerabilities
                </div>
              )}
            </Card>
          </div>

          {/* Package Health Heatmap */}
          <Card className="bg-white/5 border border-white/10 p-6 mb-8">
            <h3 className="text-lg font-bold text-white mb-4">Package Health Overview</h3>
            {packageHealthData.length > 0 ? (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {packageHealthData.map((pkg, idx) => (
                  <div key={idx} className="p-4 bg-white/5 border border-white/10 rounded-lg">
                    <div className="flex items-center justify-between mb-2">
                      <div className="font-mono text-sm text-white truncate">{pkg.packageName}</div>
                      <div className={`text-xs font-bold px-2 py-1 rounded ${
                        pkg.riskLevel === 'CRITICAL' ? 'bg-red-500/20 text-red-300' :
                        pkg.riskLevel === 'HIGH' ? 'bg-orange-500/20 text-orange-300' :
                        pkg.riskLevel === 'MEDIUM' ? 'bg-yellow-500/20 text-yellow-300' :
                        'bg-green-500/20 text-green-300'
                      }`}>
                        {pkg.riskLevel}
                      </div>
                    </div>
                    <div className="text-xs text-white/60 mb-3">{pkg.packageVersion || 'any'}</div>
                    <div className="flex items-center justify-between">
                      <div className="text-sm text-white/80">Health: {pkg.healthScore}/100</div>
                      <div className="text-xs text-white/60">{pkg.totalVulnerabilities} vulns</div>
                    </div>
                    <div className="w-full bg-white/10 rounded-full h-2 mt-2">
                      <div
                        className={`h-2 rounded-full ${
                          pkg.healthScore >= 80 ? 'bg-green-500' :
                          pkg.healthScore >= 60 ? 'bg-yellow-500' :
                          pkg.healthScore >= 40 ? 'bg-orange-500' :
                          'bg-red-500'
                        }`}
                        style={{ width: `${pkg.healthScore}%` }}
                      />
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-center py-12 text-white/40">
                No monitored packages yet. Add packages to start monitoring.
              </div>
            )}
          </Card>

          {/* Active Vulnerabilities */}
          <Card className="bg-white/5 border border-white/10 p-6">
            <h3 className="text-lg font-bold text-white mb-4">Active Vulnerabilities</h3>
            {activeVulns.length > 0 ? (
              <div className="space-y-3 max-h-96 overflow-y-auto">
                {activeVulns.slice(0, 10).map((vuln, idx) => (
                  <div key={idx} className="p-3 bg-white/5 border border-white/10 rounded-lg flex items-center justify-between">
                    <div className="flex-1">
                      <div className="font-mono text-sm text-white">{vuln.cveId}</div>
                      <div className="text-xs text-white/60">{vuln.packageName} {vuln.affectedVersion}</div>
                    </div>
                    <div className={`text-sm font-bold px-3 py-1 rounded ${
                      vuln.severity === 'CRITICAL' ? 'bg-red-500/20 text-red-300' :
                      vuln.severity === 'HIGH' ? 'bg-orange-500/20 text-orange-300' :
                      vuln.severity === 'MEDIUM' ? 'bg-yellow-500/20 text-yellow-300' :
                      'bg-green-500/20 text-green-300'
                    }`}>
                      {vuln.severity}
                    </div>
                    <div className="text-sm text-white/60 ml-4">{vuln.cvssScore}</div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-center py-12 text-white/40">
                No active vulnerabilities detected
              </div>
            )}
          </Card>
        </div>
      </div>
    </div>
  );
}
