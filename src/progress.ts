// Progress indicators for long-running operations

export interface ProgressIndicator {
  start(message: string): void;
  update(message: string): void;
  succeed(message: string): void;
  fail(message: string): void;
}

export class SpinnerProgress implements ProgressIndicator {
  private spinnerChars = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
  private currentIndex = 0;
  private interval: NodeJS.Timeout | null = null;
  private message = '';

  start(message: string): void {
    this.message = message;
    this.interval = setInterval(() => {
      process.stdout.write(`\r${this.spinnerChars[this.currentIndex]} ${this.message}`);
      this.currentIndex = (this.currentIndex + 1) % this.spinnerChars.length;
    }, 80);
  }

  update(message: string): void {
    this.message = message;
  }

  succeed(message: string): void {
    this.stop();
    process.stdout.write(`\r✓ ${message}\n`);
  }

  fail(message: string): void {
    this.stop();
    process.stdout.write(`\r✗ ${message}\n`);
  }

  private stop(): void {
    if (this.interval) {
      clearInterval(this.interval);
      this.interval = null;
    }
  }
}

export function createProgressIndicator(): ProgressIndicator {
  return new SpinnerProgress();
}

export function formatDuration(ms: number): string {
  const seconds = Math.floor(ms / 1000);
  const minutes = Math.floor(seconds / 60);
  const hours = Math.floor(minutes / 60);

  if (hours > 0) {
    return `${hours}h ${minutes % 60}m`;
  }

  if (minutes > 0) {
    return `${minutes}m ${seconds % 60}s`;
  }

  return `${seconds}s`;
}

export function formatFindingCount(count: number): string {
  if (count === 0) {
    return 'No findings';
  }

  if (count === 1) {
    return '1 finding';
  }

  return `${count} findings`;
}

export function formatPhase(phase: string): string {
  const phaseLabels: Record<string, string> = {
    pending: 'Pending',
    discovery: 'Discovery Phase',
    scanning: 'Scanning Phase',
    reviewing: 'Code Review Phase',
    compliance: 'Compliance Mapping Phase',
    validation: 'Cross-Validation Phase',
    reporting: 'Report Generation Phase',
    completed: 'Completed',
    failed: 'Failed',
  };

  return phaseLabels[phase] || phase;
}