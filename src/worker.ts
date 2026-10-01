// Temporal Worker for Application Audit

import { Worker } from '@temporalio/worker';
import * as activities from './activities';

async function run() {
  // Create worker
  const worker = await Worker.create({
    taskQueue: 'audit',
    activities,
    workflowsPath: require.resolve('./workflows'),
    maxConcurrentActivityTaskExecutions: 4,
    maxConcurrentWorkflowTaskExecutions: 10,
  });

  console.log('Starting Audit Worker...');
  console.log('Task Queue: audit');
  console.log('Press Ctrl+C to stop');

  // Run worker
  await worker.run();
}

run().catch((err) => {
  console.error('Worker failed:', err);
  process.exit(1);
});