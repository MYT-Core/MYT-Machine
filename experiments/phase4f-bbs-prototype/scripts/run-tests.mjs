import {spawnSync} from 'node:child_process';
import {delimiter, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

const experimentRoot = resolve(fileURLToPath(new URL('..', import.meta.url)));
const repositoryRoot = resolve(experimentRoot, '..', '..');

function tryPython(executable, prefixArgs = []) {
  const probe = spawnSync(executable, [
    ...prefixArgs,
    '-c',
    'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)',
  ], {
    encoding: 'utf8', windowsHide: true, shell: false,
  });
  return probe.status === 0 ? {executable, prefixArgs} : null;
}

function findPython() {
  if(process.env.MYT_PHASE4F_PYTHON) {
    return tryPython(process.env.MYT_PHASE4F_PYTHON);
  }
  const candidates = process.platform === 'win32' ?
    [['python', []], ['py', ['-3']]] :
    [['python3', []], ['python', []]];
  for(const [executable, prefixArgs] of candidates) {
    const found = tryPython(executable, prefixArgs);
    if(found) {
      return found;
    }
  }
  return null;
}

function run(executable, args, options = {}) {
  const result = spawnSync(executable, args, {
    cwd: experimentRoot,
    stdio: 'inherit',
    windowsHide: true,
    shell: false,
    ...options,
  });
  if(result.error || result.status !== 0) {
    process.exit(result.status ?? 1);
  }
}

const python = findPython();
if(!python) {
  throw new Error(
    'Phase 4F integration tests require Python 3.10+; set MYT_PHASE4F_PYTHON'
  );
}
const pythonPath = [
  resolve(repositoryRoot, 'src'),
  process.env.PYTHONPATH,
].filter(Boolean).join(delimiter);

run(python.executable, [
  ...python.prefixArgs,
  '-m', 'unittest', 'discover', '-s', 'test', '-p', 'test_*.py', '-v',
], {env: {...process.env, PYTHONPATH: pythonPath}});

run(process.execPath, ['--test', '--test-reporter=spec'], {
  env: {
    ...process.env,
    MYT_PHASE4F_PYTHON: python.executable,
    PYTHONPATH: pythonPath,
  },
});
