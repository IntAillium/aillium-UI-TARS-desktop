import { fork, spawn, type ChildProcess } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { join } from 'node:path';
import type { DesktopControlIdentity } from './desktopControlSessions';
import { requestRemoteFenceCancellation } from './desktopRemoteFence';
import type {
  DesktopActionProcessCommand,
  DesktopActionProcessResponse,
  IsolatedDesktopSurface,
} from './desktopActionProtocol';

type ForkChild = Pick<
  ChildProcess,
  'connected' | 'pid' | 'send' | 'kill' | 'once' | 'removeAllListeners'
>;

export type DesktopActionFork = (
  modulePath: string,
  args: string[],
  options: Parameters<typeof fork>[2],
) => ForkChild;

const WORKER_ENV_ALLOWLIST = [
  'PATH',
  'Path',
  'SystemRoot',
  'WINDIR',
  'HOME',
  'USERPROFILE',
  'APPDATA',
  'LOCALAPPDATA',
  'TEMP',
  'TMP',
  'TMPDIR',
  'LANG',
  'LC_ALL',
  'LC_CTYPE',
  'DISPLAY',
  'WAYLAND_DISPLAY',
  'XDG_RUNTIME_DIR',
  'XDG_CONFIG_HOME',
  'XDG_CACHE_HOME',
  'DBUS_SESSION_BUS_ADDRESS',
  'CHROME_PATH',
  'PLAYWRIGHT_BROWSERS_PATH',
] as const;

export function buildDesktopActionWorkerEnvironment(
  source: NodeJS.ProcessEnv = process.env,
): NodeJS.ProcessEnv {
  const environment: NodeJS.ProcessEnv = {};
  for (const name of WORKER_ENV_ALLOWLIST) {
    const value = source[name];
    if (value !== undefined) environment[name] = value;
  }
  return {
    ...environment,
    ELECTRON_RUN_AS_NODE: '1',
    AILLIUM_DESKTOP_ACTION_PARENT_PID: String(process.pid),
  };
}

function hasErrorCode(error: unknown, code: string) {
  return (
    typeof error === 'object' &&
    error !== null &&
    'code' in error &&
    error.code === code
  );
}

function terminateWindowsProcessTree(child: ForkChild) {
  if (!child.pid) {
    child.kill('SIGKILL');
    return Promise.resolve(true);
  }
  return new Promise<boolean>((resolve) => {
    let taskkill: ChildProcess;
    try {
      taskkill = spawn('taskkill', ['/PID', String(child.pid), '/T', '/F'], {
        stdio: 'ignore',
        windowsHide: true,
      });
    } catch {
      child.kill('SIGKILL');
      resolve(false);
      return;
    }
    taskkill.once('error', () => {
      child.kill('SIGKILL');
      resolve(false);
    });
    taskkill.once('exit', (code) => resolve(code === 0));
  });
}

function terminatePosixProcessTree(child: ForkChild) {
  if (!child.pid) {
    child.kill('SIGKILL');
    return Promise.resolve(true);
  }
  try {
    // A successful process-group SIGKILL is the POSIX teardown proof: neither
    // the worker nor any inherited descendant can catch it or execute again.
    // The direct child's exit event is still required before the action settles.
    process.kill(-child.pid, 'SIGKILL');
  } catch (error) {
    if (!hasErrorCode(error, 'ESRCH')) return Promise.resolve(false);
  }
  return Promise.resolve(true);
}

export type DesktopProcessTreeController = {
  detached: boolean;
  terminate: (child: ForkChild) => Promise<boolean>;
};

export function createDesktopProcessTreeController(
  platform = process.platform,
): DesktopProcessTreeController {
  return platform === 'win32'
    ? { detached: false, terminate: terminateWindowsProcessTree }
    : { detached: true, terminate: terminatePosixProcessTree };
}

function targetFromIdentity(identity: DesktopControlIdentity) {
  const { expiresAt: _expiresAt, ...target } = identity;
  return target;
}

function sameResponseIdentity(
  response: DesktopActionProcessResponse,
  command: DesktopActionProcessCommand,
) {
  return (
    response.operationId === command.operationId &&
    JSON.stringify(response.identity) === JSON.stringify(command.identity)
  );
}

export class IsolatedDesktopAction {
  private child: ForkChild | null = null;
  private terminated = false;
  private teardownProof: Promise<boolean> | null = null;
  private operationId: string | null = null;
  private cancellationOperation: {
    identityKey: string;
    operationId: string;
  } | null = null;

  constructor(
    private readonly identity: DesktopControlIdentity,
    private readonly input: {
      surface: IsolatedDesktopSurface;
      action: string;
      arguments: Record<string, unknown>;
      searchEngine?: DesktopActionProcessCommand['searchEngine'];
      remoteBrowserCdpUrl?: string;
      remoteComputer?: DesktopActionProcessCommand['remoteComputer'];
      display?: DesktopActionProcessCommand['display'];
    },
    private readonly forkChild: DesktopActionFork = fork,
    private readonly workerPath = join(__dirname, 'desktopActionWorker.js'),
    private readonly processTree = createDesktopProcessTreeController(),
  ) {}

  async run(signal: AbortSignal): Promise<unknown> {
    if (signal.aborted) throw signal.reason;
    const command: DesktopActionProcessCommand = {
      operationId: randomUUID(),
      identity: targetFromIdentity(this.identity),
      ...this.input,
    };
    this.operationId = command.operationId;
    const child = this.forkChild(this.workerPath, [], {
      env: {
        ...buildDesktopActionWorkerEnvironment(),
      },
      detached: this.processTree.detached,
      stdio: ['ignore', 'ignore', 'ignore', 'ipc'],
      serialization: 'advanced',
    });
    this.child = child;

    return await new Promise<unknown>((resolve, reject) => {
      let response: DesktopActionProcessResponse | null = null;
      let terminalError: Error | null = null;
      let settled = false;
      const finish = (error?: Error) => {
        if (settled) return;
        settled = true;
        signal.removeEventListener('abort', onAbort);
        child.removeAllListeners();
        this.child = null;
        if (error) reject(error);
        else if (!response?.ok) {
          reject(
            new Error(response?.error || 'Isolated desktop action failed'),
          );
        } else resolve(response.result);
      };
      const terminateWith = (error: Error) => {
        terminalError = error;
        this.terminate();
      };
      const onAbort = () =>
        terminateWith(
          signal.reason instanceof Error
            ? signal.reason
            : new Error('Isolated desktop action was cancelled'),
        );
      signal.addEventListener('abort', onAbort, { once: true });
      child.once('message', (message: unknown) => {
        if (this.terminated) return;
        const candidate = message as DesktopActionProcessResponse;
        if (!sameResponseIdentity(candidate, command)) {
          terminateWith(
            new Error(
              'Isolated desktop response identity did not match its fence',
            ),
          );
          return;
        }
        response = candidate;
      });
      child.once('error', (error: Error) => terminateWith(error));
      child.once('exit', (code, exitSignal) => {
        void (async () => {
          if (!response && !this.terminated) {
            terminateWith(
              new Error(
                `Isolated desktop action exited without proof (${code ?? exitSignal ?? 'unknown'})`,
              ),
            );
          }
          if (this.terminated) {
            const verified = await (this.teardownProof ??
              Promise.resolve(false));
            // A settled promise would let the session registry claim verified
            // teardown. Keep it pending when the OS cannot prove the whole
            // process tree is gone (notably a failed Windows taskkill /T).
            if (!verified) return;
          }
          if (terminalError) finish(terminalError);
          else if (this.terminated) {
            finish(new Error('Isolated desktop action was force-terminated'));
          } else if (response) finish();
        })();
      });
      child.send(command, (error) => {
        if (error) terminateWith(error);
      });
      if (signal.aborted) onAbort();
    });
  }

  terminate(): void {
    this.terminated = true;
    const child = this.child;
    if (!child) return;
    this.teardownProof ??= this.processTree.terminate(child);
  }

  async cancelRemoteFence(
    nextIdentity: DesktopControlIdentity,
    desktopControlToken: string,
    signal?: AbortSignal,
  ) {
    const descriptor = this.input.remoteComputer;
    if (this.input.surface !== 'remote_computer' || !descriptor) return null;
    const original = targetFromIdentity(this.identity);
    if (
      nextIdentity.tenantId !== original.tenantId ||
      nextIdentity.workOrderId !== original.workOrderId ||
      nextIdentity.authorityType !== original.authorityType ||
      nextIdentity.authorityId !== original.authorityId ||
      nextIdentity.runId !== original.runId ||
      nextIdentity.runStepId !== original.runStepId ||
      nextIdentity.desktopSessionId !== original.desktopSessionId ||
      nextIdentity.executorId !== original.executorId ||
      nextIdentity.attempt < original.attempt ||
      BigInt(nextIdentity.fenceToken) < BigInt(original.fenceToken) ||
      nextIdentity.cancellationGeneration <= original.cancellationGeneration
    ) {
      throw new Error(
        'Remote computer cancellation requires the same lineage and a newer cancellation generation',
      );
    }
    if (!desktopControlToken) {
      throw new Error('Signed desktop-control cancellation token is required');
    }
    const target = targetFromIdentity(nextIdentity);
    const identityKey = JSON.stringify(target);
    if (
      !this.cancellationOperation ||
      this.cancellationOperation.identityKey !== identityKey
    ) {
      this.cancellationOperation = {
        identityKey,
        operationId: randomUUID(),
      };
    }
    const result = await requestRemoteFenceCancellation(
      descriptor,
      this.cancellationOperation.operationId,
      desktopControlToken,
      target,
      signal,
    );
    if (
      result.cancelledOperationId !== null &&
      result.cancelledOperationId !== this.operationId
    ) {
      throw new Error(
        'Remote gateway cancellation referenced another desktop operation',
      );
    }
    return result;
  }
}
