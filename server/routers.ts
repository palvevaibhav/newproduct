import { COOKIE_NAME } from "@shared/const";
import { getSessionCookieOptions } from "./_core/cookies";
import { systemRouter } from "./_core/systemRouter";
import { publicProcedure, router, protectedProcedure } from "./_core/trpc";

export const appRouter = router({
  system: systemRouter,
  auth: router({
    me: publicProcedure.query(opts => opts.ctx.user),
    logout: publicProcedure.mutation(({ ctx }) => {
      const cookieOptions = getSessionCookieOptions(ctx.req);
      ctx.res.clearCookie(COOKIE_NAME, { ...cookieOptions, maxAge: -1 });
      return {
        success: true,
      } as const;
    }),
  }),

  security: router({
    /**
     * Main query endpoint: accepts any security query and returns RAG-synthesized results
     */
    query: protectedProcedure
      .input((val: unknown) => {
        if (typeof val === 'string') return val;
        throw new Error('Query must be a string');
      })
      .mutation(async ({ input: query, ctx }) => {
        const { classifyQuery } = await import('./queryClassifier');
        const { runRAGPipeline } = await import('./ragPipeline');
        const { storeSecurityQuery, recordNotification } = await import('./securityDb');
        const { notifyOwner } = await import('./_core/notification');

        try {
          // Classify the query
          const classification = classifyQuery(query);

          if (!classification.isSecurityRelated) {
            return {
              success: false,
              error: 'Query does not appear to be security-related. Please ask about CVEs, vulnerabilities, packages, or security threats.',
              data: null,
            };
          }

          // Run RAG pipeline
          const ragResult = await runRAGPipeline(query, classification);

          // Store query and results
          const storedQuery = await storeSecurityQuery(ctx.user.id, query, classification, ragResult);

          // Check if critical and notify owner
          if (ragResult.synthesis.riskLevel === 'CRITICAL' && ragResult.synthesis.cvssScore && ragResult.synthesis.cvssScore > 8.0) {
            await recordNotification(
              ctx.user.id,
              'critical_cve',
              `Critical Vulnerability Detected: ${query}`,
              `CVSS Score: ${ragResult.synthesis.cvssScore}\n\n${ragResult.synthesis.summary}`,
              ragResult.synthesis.cvssScore,
              undefined,
              storedQuery?.id
            );

            // Notify project owner
            await notifyOwner({
              title: `🚨 Critical CVE Alert: ${query}`,
              content: `A critical vulnerability (CVSS ${ragResult.synthesis.cvssScore}) has been queried.\n\n${ragResult.synthesis.summary}`,
            });
          }

          return {
            success: true,
            data: ragResult,
            queryId: storedQuery?.id,
          };
        } catch (error) {
          console.error('Security query error:', error);
          return {
            success: false,
            error: error instanceof Error ? error.message : 'Failed to process security query',
            data: null,
          };
        }
      }),

    /**
     * Get recent queries for the current user
     */
    recentQueries: protectedProcedure
      .input((val: unknown) => {
        const limit = typeof val === 'number' ? val : 10;
        return Math.min(Math.max(limit, 1), 50);
      })
      .query(async ({ input: limit, ctx }) => {
        const { getRecentQueries } = await import('./securityDb');
        return await getRecentQueries(ctx.user.id, limit);
      }),

    /**
     * Get critical queries (CVSS > 8.0)
     */
    criticalQueries: protectedProcedure
      .query(async ({ ctx }) => {
        const { getCriticalQueries } = await import('./securityDb');
        return await getCriticalQueries(ctx.user.id);
      }),

    /**
     * Add a package to monitoring
     */
    addMonitoredPackage: protectedProcedure
      .input((val: unknown) => {
        if (typeof val === 'object' && val !== null) {
          const input = val as Record<string, unknown>;
          return {
            packageName: String(input.packageName || ''),
            packageVersion: input.packageVersion ? String(input.packageVersion) : undefined,
            ecosystem: input.ecosystem ? String(input.ecosystem) : 'npm',
          };
        }
        throw new Error('Invalid input');
      })
      .mutation(async ({ input, ctx }) => {
        const { addMonitoredPackage } = await import('./securityDb');
        await addMonitoredPackage(ctx.user.id, input.packageName, input.packageVersion, input.ecosystem);
        return { success: true };
      }),

    /**
     * Get monitored packages
     */
    monitoredPackages: protectedProcedure
      .query(async ({ ctx }) => {
        const { getMonitoredPackages } = await import('./securityDb');
        return await getMonitoredPackages(ctx.user.id);
      }),

    /**
     * Get notification history
     */
    notificationHistory: protectedProcedure
      .input((val: unknown) => {
        const limit = typeof val === 'number' ? val : 20;
        return Math.min(Math.max(limit, 1), 100);
      })
      .query(async ({ input: limit, ctx }) => {
        const { getNotificationHistory } = await import('./securityDb');
        return await getNotificationHistory(ctx.user.id, limit);
      }),

    /**
     * Local-RAG library vulnerability intelligence report.
     */
    libraryRisk: protectedProcedure
      .input((val: unknown) => {
        if (typeof val === 'object' && val !== null) {
          const input = val as Record<string, unknown>;
          return {
            packageName: String(input.packageName || ''),
            packageVersion: input.packageVersion ? String(input.packageVersion) : undefined,
          };
        }
        throw new Error('Invalid input');
      })
      .mutation(async ({ input }) => {
        if (!input.packageName) {
          throw new Error('packageName is required');
        }

        const { buildLibraryRiskReport } = await import('./securityIntelligence');
        return await buildLibraryRiskReport(input.packageName, input.packageVersion);
      }),

    /**
     * Analyze a local git commit and infer security remediation details.
     */
    analyzePatch: protectedProcedure
      .input((val: unknown) => {
        if (typeof val === 'string') return val.trim();
        throw new Error('commit hash must be a string');
      })
      .mutation(async ({ input: commitHash }) => {
        if (!commitHash) {
          throw new Error('commit hash is required');
        }

        const { analyzePatchCommit } = await import('./securityIntelligence');
        return await analyzePatchCommit(commitHash);
      }),

    /**
     * Lookup a CVE across ingested sources and return normalized intelligence.
     */
    cveLookup: protectedProcedure
      .input((val: unknown) => {
        if (typeof val === 'string') return val.trim();
        throw new Error('CVE ID must be a string');
      })
      .mutation(async ({ input: cveId }) => {
        const { buildCveIntelReport } = await import('./securityIntelligence');
        return await buildCveIntelReport(cveId);
      }),
  }),

  dashboard: router({
    /**
     * Get dashboard overview with current security metrics
     */
    overview: protectedProcedure
      .query(async ({ ctx }) => {
        const {
          getDashboardSnapshot,
          getVulnerabilitySeverityDistribution,
          getPackageHealthScores,
        } = await import('./dashboardDb');

        const snapshot = await getDashboardSnapshot(ctx.user.id);
        const severityDistribution = await getVulnerabilitySeverityDistribution(ctx.user.id);
        const packageHealthScores = await getPackageHealthScores(ctx.user.id);

        return {
          snapshot,
          severityDistribution,
          packageHealthScores,
        };
      }),

    /**
     * Get vulnerability trend data for a date range
     */
    vulnerabilityTrend: protectedProcedure
      .input((val: unknown) => {
        if (typeof val === 'object' && val !== null) {
          const input = val as Record<string, unknown>;
          return {
            days: typeof input.days === 'number' ? Math.min(Math.max(input.days, 1), 90) : 30,
          };
        }
        throw new Error('Invalid input');
      })
      .query(async ({ input, ctx }) => {
        const { getDashboardSnapshotsTrend } = await import('./dashboardDb');

        const endDate = new Date();
        const startDate = new Date();
        startDate.setDate(startDate.getDate() - input.days);

        return await getDashboardSnapshotsTrend(ctx.user.id, startDate, endDate);
      }),

    /**
     * Get package-specific metrics trend
     */
    packageTrend: protectedProcedure
      .input((val: unknown) => {
        if (typeof val === 'object' && val !== null) {
          const input = val as Record<string, unknown>;
          return {
            packageId: Number(input.packageId || 0),
            days: typeof input.days === 'number' ? Math.min(Math.max(input.days, 1), 90) : 30,
          };
        }
        throw new Error('Invalid input');
      })
      .query(async ({ input, ctx }) => {
        const { getPackageMetricsTrend } = await import('./dashboardDb');

        const endDate = new Date();
        const startDate = new Date();
        startDate.setDate(startDate.getDate() - input.days);

        return await getPackageMetricsTrend(ctx.user.id, input.packageId, startDate, endDate);
      }),

    /**
     * Get vulnerability timeline for a package
     */
    vulnerabilityTimeline: protectedProcedure
      .input((val: unknown) => {
        if (typeof val === 'object' && val !== null) {
          const input = val as Record<string, unknown>;
          return {
            packageId: Number(input.packageId || 0),
            days: typeof input.days === 'number' ? Math.min(Math.max(input.days, 1), 90) : 30,
          };
        }
        throw new Error('Invalid input');
      })
      .query(async ({ input, ctx }) => {
        const { getVulnerabilityTimeline } = await import('./dashboardDb');

        const endDate = new Date();
        const startDate = new Date();
        startDate.setDate(startDate.getDate() - input.days);

        return await getVulnerabilityTimeline(ctx.user.id, input.packageId, startDate, endDate);
      }),

    /**
     * Get active vulnerabilities
     */
    activeVulnerabilities: protectedProcedure
      .query(async ({ ctx }) => {
        const { getActiveVulnerabilities } = await import('./dashboardDb');
        return await getActiveVulnerabilities(ctx.user.id);
      }),
  }),
});

export type AppRouter = typeof appRouter;
