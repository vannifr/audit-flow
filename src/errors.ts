import { ApplicationFailure } from '@temporalio/activity';
import logger from './logger';

/**
 * Custom error types for the audit application
 */
export const ErrorTypes = {
  INVALID_REPO: 'InvalidRepoError',
  VALIDATION_ERROR: 'ValidationError',
  SECURITY_ERROR: 'SecurityError',
  SCAN_ERROR: 'ScanError',
  CONFIG_ERROR: 'ConfigurationError',
  TIMEOUT_ERROR: 'TimeoutError',
} as const;

/**
 * Creates an ApplicationFailure for invalid repository URLs
 */
export function createInvalidRepoError(message: string, details?: Record<string, any>): never {
  logger.error({ type: ErrorTypes.INVALID_REPO, message, details }, 'Invalid repository error');
  throw ApplicationFailure.create({
    message,
    type: ErrorTypes.INVALID_REPO,
    nonRetryable: true,
    details: details ? [details] : undefined,
  });
}

/**
 * Creates an ApplicationFailure for validation errors
 */
export function createValidationError(message: string, field?: string, value?: any): never {
  logger.error({ type: ErrorTypes.VALIDATION_ERROR, message, field, value }, 'Validation error');
  throw ApplicationFailure.create({
    message,
    type: ErrorTypes.VALIDATION_ERROR,
    nonRetryable: true,
    details: [{ field, value }],
  });
}

/**
 * Creates an ApplicationFailure for security violations
 */
export function createSecurityError(message: string, violation: string): never {
  logger.error({ type: ErrorTypes.SECURITY_ERROR, message, violation }, 'Security error');
  throw ApplicationFailure.create({
    message,
    type: ErrorTypes.SECURITY_ERROR,
    nonRetryable: true,
    details: [{ violation }],
  });
}

/**
 * Creates an ApplicationFailure for scan failures
 */
export function createScanError(tool: string, message: string, retryable: boolean = true): never {
  logger.error({ type: ErrorTypes.SCAN_ERROR, tool, message, retryable }, 'Scan error');
  throw ApplicationFailure.create({
    message: `${tool} scan failed: ${message}`,
    type: ErrorTypes.SCAN_ERROR,
    nonRetryable: !retryable,
    details: [{ tool }],
  });
}

/**
 * Creates an ApplicationFailure for configuration errors
 */
export function createConfigError(message: string, missingKey?: string): never {
  logger.error({ type: ErrorTypes.CONFIG_ERROR, message, missingKey }, 'Configuration error');
  throw ApplicationFailure.create({
    message,
    type: ErrorTypes.CONFIG_ERROR,
    nonRetryable: true,
    details: [{ missingKey }],
  });
}

/**
 * Creates an ApplicationFailure for timeout errors
 */
export function createTimeoutError(operation: string, timeoutMs: number): never {
  logger.error({ type: ErrorTypes.TIMEOUT_ERROR, operation, timeoutMs }, 'Timeout error');
  throw ApplicationFailure.create({
    message: `${operation} timed out after ${timeoutMs}ms`,
    type: ErrorTypes.TIMEOUT_ERROR,
    nonRetryable: false, // Timeouts are often transient
    details: [{ operation, timeoutMs }],
  });
}

/**
 * Wraps an async operation with standardized error handling
 */
export async function withErrorHandling<T>(
  operation: string,
  fn: () => Promise<T>,
  errorType: string = ErrorTypes.SCAN_ERROR
): Promise<T> {
  try {
    return await fn();
  } catch (error) {
    if (error instanceof ApplicationFailure) {
      throw error;
    }

    logger.error({ operation, error: String(error) }, 'Operation failed');

    throw ApplicationFailure.create({
      message: `${operation} failed: ${error instanceof Error ? error.message : String(error)}`,
      type: errorType,
      nonRetryable: false,
    });
  }
}

/**
 * Checks if an error is retryable
 */
export function isRetryableError(error: unknown): boolean {
  if (error instanceof ApplicationFailure) {
    return !error.nonRetryable;
  }
  return true; // Default to retryable for unknown errors
}

/**
 * Gets error message from unknown error type
 */
export function getErrorMessage(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }
  if (typeof error === 'string') {
    return error;
  }
  return 'Unknown error';
}