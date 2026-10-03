import { ApplicationFailure } from '@temporalio/activity';

export function validateRepoUrl(url: string): void {
  const githubPattern = /^https:\/\/github\.com\/[a-zA-Z0-9_-]+\/[a-zA-Z0-9_.-]+(\.git)?$/;

  if (!githubPattern.test(url)) {
    throw ApplicationFailure.create({
      message: 'Invalid repository URL. Only GitHub URLs in format https://github.com/owner/repo are allowed',
      type: 'InvalidRepoError',
    });
  }

  if (url.includes('..') || url.includes(';') || url.includes('|') || url.includes('&')) {
    throw ApplicationFailure.create({
      message: 'Invalid repository URL: contains forbidden characters',
      type: 'InvalidRepoError',
    });
  }
}
