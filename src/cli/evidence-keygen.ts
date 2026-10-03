import { generateSigningKey } from '../evidence/sign';

export interface KeygenIo {
  stdout: (s: string) => void;
  stderr: (s: string) => void;
}

const USAGE = 'usage: npm run evidence:keygen -- <private-key-path>\n';

function plain(value: string): string {
  return /^[\x20-\x7e]*$/.test(value) ? value : JSON.stringify(value);
}

export async function runKeygenCli(argv: string[], io: KeygenIo): Promise<number> {
  if (argv.length !== 1 || argv[0].length === 0 || argv[0].startsWith('-')) {
    io.stderr(USAGE);
    return 2;
  }
  try {
    const { keyId, publicKeyPath } = await generateSigningKey(argv[0]);
    io.stdout(`keyId: ${keyId}\npublic key: ${plain(publicKeyPath)}\nPublish the public key to verifiers; keep the private key outside the evidence folder.\n`);
    return 0;
  } catch (error) {
    io.stderr(`${error instanceof Error ? plain(error.message) : 'key generation failed'}\n`);
    return 1;
  }
}

async function main(): Promise<void> {
  process.exitCode = await runKeygenCli(process.argv.slice(2), {
    stdout: (s) => process.stdout.write(s),
    stderr: (s) => process.stderr.write(s),
  });
}

if (require.main === module) {
  void main();
}
