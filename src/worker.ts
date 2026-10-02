// Temporal Worker for Application Audit

import { Worker } from '@temporalio/worker';
import * as activities from './activities';
import logger from './logger';

async function run() {
  // Create worker
  const worker = await Worker.create({
    taskQueue: 'audit',
    activities,
    workflowsPath: require.resolve('./workflows'),
    maxConcurrentActivityTaskExecutions: 4,
    maxConcurrentWorkflowTaskExecutions: 10,
  });

  logger.info('Starting Audit Worker...');
  logger.info({ taskQueue: 'audit' }, 'Worker configured');
  logger.info('Press Ctrl+C to stop');

  // Run worker
  await worker.run();
}

run().catch((err) => {
  logger.error({ error: err }, 'Worker failed');
  process.exit(1);
});