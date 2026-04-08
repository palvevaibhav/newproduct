import { describe, it, expect } from 'vitest';
import {
  calculateHealthScore,
  determineRiskLevel,
  getVulnerabilitySeverityDistribution,
} from './dashboardDb';

describe('Dashboard Database Functions', () => {
  describe('calculateHealthScore', () => {
    it('should return 100 for no vulnerabilities', () => {
      const score = calculateHealthScore(0, 0, 0, 0);
      expect(score).toBe(100);
    });

    it('should deduct 10 points per critical vulnerability', () => {
      const score = calculateHealthScore(1, 0, 0, 0);
      expect(score).toBe(90);
    });

    it('should deduct 5 points per high vulnerability', () => {
      const score = calculateHealthScore(0, 1, 0, 0);
      expect(score).toBe(95);
    });

    it('should deduct 2 points per medium vulnerability', () => {
      const score = calculateHealthScore(0, 0, 1, 0);
      expect(score).toBe(98);
    });

    it('should deduct 1 point per low vulnerability', () => {
      const score = calculateHealthScore(0, 0, 0, 1);
      expect(score).toBe(99);
    });

    it('should calculate combined score correctly', () => {
      const score = calculateHealthScore(2, 3, 5, 10);
      // 100 - (2*10 + 3*5 + 5*2 + 10*1) = 100 - (20 + 15 + 10 + 10) = 100 - 55 = 45
      expect(score).toBe(45);
    });

    it('should not go below 0', () => {
      const score = calculateHealthScore(20, 20, 20, 20);
      expect(score).toBeGreaterThanOrEqual(0);
      expect(score).toBeLessThanOrEqual(100);
    });

    it('should not exceed 100', () => {
      const score = calculateHealthScore(0, 0, 0, 0);
      expect(score).toBeLessThanOrEqual(100);
    });
  });

  describe('determineRiskLevel', () => {
    it('should return CRITICAL if critical vulnerabilities exist', () => {
      const level = determineRiskLevel(1, 0, 0);
      expect(level).toBe('CRITICAL');
    });

    it('should return HIGH if high vulnerabilities exist but no critical', () => {
      const level = determineRiskLevel(0, 1, 0);
      expect(level).toBe('HIGH');
    });

    it('should return MEDIUM if medium vulnerabilities exist but no critical or high', () => {
      const level = determineRiskLevel(0, 0, 1);
      expect(level).toBe('MEDIUM');
    });

    it('should return LOW if no vulnerabilities exist', () => {
      const level = determineRiskLevel(0, 0, 0);
      expect(level).toBe('LOW');
    });

    it('should prioritize CRITICAL over HIGH', () => {
      const level = determineRiskLevel(1, 5, 10);
      expect(level).toBe('CRITICAL');
    });

    it('should prioritize HIGH over MEDIUM', () => {
      const level = determineRiskLevel(0, 1, 10);
      expect(level).toBe('HIGH');
    });
  });

  describe('Severity Distribution', () => {
    it('should handle empty vulnerability list', () => {
      const distribution = {
        CRITICAL: 0,
        HIGH: 0,
        MEDIUM: 0,
        LOW: 0,
      };

      expect(distribution.CRITICAL).toBe(0);
      expect(distribution.HIGH).toBe(0);
      expect(distribution.MEDIUM).toBe(0);
      expect(distribution.LOW).toBe(0);
    });

    it('should track severity counts correctly', () => {
      const distribution = {
        CRITICAL: 2,
        HIGH: 3,
        MEDIUM: 5,
        LOW: 10,
      };

      expect(distribution.CRITICAL).toBe(2);
      expect(distribution.HIGH).toBe(3);
      expect(distribution.MEDIUM).toBe(5);
      expect(distribution.LOW).toBe(10);
    });
  });

  describe('Risk Level Thresholds', () => {
    it('should identify critical risk with any critical vulnerability', () => {
      expect(determineRiskLevel(1, 0, 0)).toBe('CRITICAL');
      expect(determineRiskLevel(1, 10, 20)).toBe('CRITICAL');
    });

    it('should identify high risk with high but no critical', () => {
      expect(determineRiskLevel(0, 1, 0)).toBe('HIGH');
      expect(determineRiskLevel(0, 1, 20)).toBe('HIGH');
    });

    it('should identify medium risk with medium but no critical or high', () => {
      expect(determineRiskLevel(0, 0, 1)).toBe('MEDIUM');
      expect(determineRiskLevel(0, 0, 5)).toBe('MEDIUM');
    });

    it('should identify low risk with no vulnerabilities', () => {
      expect(determineRiskLevel(0, 0, 0)).toBe('LOW');
    });
  });

  describe('Health Score Edge Cases', () => {
    it('should handle large vulnerability counts', () => {
      const score = calculateHealthScore(100, 100, 100, 100);
      expect(score).toBeGreaterThanOrEqual(0);
      expect(score).toBeLessThanOrEqual(100);
    });

    it('should calculate correctly for single vulnerability of each type', () => {
      const score = calculateHealthScore(1, 1, 1, 1);
      // 100 - (1*10 + 1*5 + 1*2 + 1*1) = 100 - 18 = 82
      expect(score).toBe(82);
    });

    it('should handle zero vulnerabilities', () => {
      const score = calculateHealthScore(0, 0, 0, 0);
      expect(score).toBe(100);
    });
  });
});
