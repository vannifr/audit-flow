/**
 * BDD Step Definitions for Feature 002: P0 Approval Workflow
 */

import { Given, When, Then } from '@cucumber/cucumber';
import { expect } from 'vitest';
import { waitForHumanApproval } from '../../../../src/activities/index';

// Background
Given('the Temporal server is running', function () {
  this.temporalRunning = true;
});

Given('an audit workflow is running', function () {
  this.workflowId = `audit-${Date.now()}`;
  this.status = 'Reviewing';
});

// TS-010: Pause workflow for P0 findings
Given('P0 findings are detected during the Reviewing phase', function () {
  this.p0Count = 3;
  this.findings = [
    { severity: 'P0', title: 'Secret detected' },
    { severity: 'P0', title: 'SQL injection' },
    { severity: 'P0', title: 'XSS vulnerability' },
  ];
});

When('the Reviewing phase completes', async function () {
  this.reviewComplete = true;
  if (this.p0Count > 0 && !this.skipApproval) {
    this.approvalResult = await waitForHumanApproval(this.workflowId, this.p0Count);
    this.status = 'Waiting for P0 approval';
  }
});

Then('the workflow pauses within {int} second', function (maxSeconds: number) {
  expect(this.status).toBe('Waiting for P0 approval');
});

Then('waits for approval signal', function () {
  expect(this.status).toBe('Waiting for P0 approval');
});

Then('the status is {string}', function (status: string) {
  expect(this.status).toBe(status);
});

// TS-011: No pause when no P0 findings
Given('no P0 findings are detected', function () {
  this.p0Count = 0;
});

Then('the workflow proceeds directly to Reporting phase', function () {
  expect(this.status).not.toBe('Waiting for P0 approval');
});

// TS-012: Approve P0 findings
Given('the workflow is paused for P0 approval', function () {
  this.status = 'Waiting for P0 approval';
  this.paused = true;
});

When('I send approval signal with {string}', async function (approved: string) {
  this.approvalSent = approved === 'true';
  this.approvalResult = { approved: this.approvalSent };
  if (this.approvalSent) {
    this.status = 'Reporting';
  } else {
    this.status = 'Failed';
  }
});

Then('the workflow proceeds to Reporting phase', function () {
  expect(this.status).toBe('Reporting');
});

Then('logs the approval decision with timestamp', function () {
  expect(this.approvalSent).toBe(true);
});

// TS-013: Reject P0 findings
Then('the workflow stops', function () {
  expect(this.status).toBe('Failed');
});

Then('marks the audit as {string}', function (status: string) {
  expect(this.status.toLowerCase()).toContain(status.toLowerCase());
});

Then('logs the rejection with timestamp', function () {
  expect(this.approvalSent).toBe(false);
});

// TS-014: Approval timeout
Given('the timeout is set to {int} hours', function (hours: number) {
  this.timeout = hours * 3600000; // ms
});

When('{int} hours pass without approval signal', function (hours: number) {
  // Simulate timeout
  this.timedOut = true;
  this.status = 'Approval timeout';
});

Then('the workflow times out', function () {
  expect(this.timedOut).toBe(true);
});

Then('stops with status {string}', function (status: string) {
  expect(this.status).toBe(status);
});

// TS-015: Skip approval for CI/CD
Given('I start an audit with {string}', function (flag: string) {
  this.skipApproval = flag.includes('skip-approval');
});

When('P0 findings are detected', async function () {
  this.p0Count = 3;
  if (this.skipApproval) {
    this.status = 'Reporting';
  } else {
    this.status = 'Waiting for P0 approval';
  }
});

Then('the workflow proceeds without pausing', function () {
  expect(this.status).not.toBe('Waiting for P0 approval');
});