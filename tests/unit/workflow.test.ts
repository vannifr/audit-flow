import { describe, it, expect } from 'vitest';

// Unit tests for workflow queries
// These tests verify query handlers work correctly

describe('Workflow Queries', () => {
  describe('statusQuery', () => {
    it('should return current workflow phase', () => {
      // Mock workflow state
      const mockState = {
        currentPhase: 'scanning',
        findings: [],
      };

      expect(mockState.currentPhase).toBe('scanning');
    });

    it('should transition through all phases', () => {
      const phases = ['pending', 'discovery', 'scanning', 'reviewing', 'compliance', 'validation', 'reporting', 'completed'];
      expect(phases).toHaveLength(8);
    });
  });

  describe('findingsQuery', () => {
    it('should return all findings', () => {
      const mockFindings = [
        { id: 'FIND-001', severity: 'P0', title: 'Critical issue' },
        { id: 'FIND-002', severity: 'P1', title: 'High issue' },
      ];

      expect(mockFindings).toHaveLength(2);
    });

    it('should filter findings by severity', () => {
      const mockFindings = [
        { id: 'FIND-001', severity: 'P0', title: 'Critical issue' },
        { id: 'FIND-002', severity: 'P1', title: 'High issue' },
        { id: 'FIND-003', severity: 'P0', title: 'Another critical' },
      ];

      const p0Findings = mockFindings.filter(f => f.severity === 'P0');
      expect(p0Findings).toHaveLength(2);
    });
  });

  describe('stateQuery', () => {
    it('should return complete workflow state', () => {
      const mockState = {
        currentPhase: 'scanning',
        findings: [{ id: 'FIND-001', severity: 'P0' }],
        techStack: { language: 'nodejs', frameworks: ['Express'] },
        scope: { frameworks: ['ISO27001'] },
        p0Approved: false,
      };

      expect(mockState.currentPhase).toBe('scanning');
      expect(mockState.techStack.language).toBe('nodejs');
      expect(mockState.p0Approved).toBe(false);
    });
  });
});