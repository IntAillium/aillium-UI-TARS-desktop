import { fork } from 'node:child_process';
import { EventEmitter } from 'node:events';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { createServer } from 'node:net';
import { join } from 'node:path';
import { describe, expect, it, vi } from 'vitest';
import {
  buildDesktopActionWorkerEnvironment,
  createDesktopProcessTreeController,
  IsolatedDesktopAction,
  type DesktopActionFork,
  type DesktopProcessTreeController,
} from './desktopActionProcess';
import type {
  DesktopActionProcessCommand,
  DesktopActionProcessResponse,
} from './desktopActionProtocol';
import type { DesktopControlIdentity } from './desktopControlSessions';

const identity: DesktopControlIdentity = {
  tenantId: 'tenant-1',
  workOrderId: 'work-1',
  authorityType: 'agent',
  authorityId: 'agent-1',
  runId: 'run-1',
  runStepId: 'step-1',
  desktopSessionId: 'desktop-1',
  attempt: 2,
  executorId: 'executor-1',
  fenceToken: '8',
  cancellationGeneration: 1,
  expiresAt: Math.floor(Date.now() / 1_000) + 60,
};

class FakeChild extends EventEmitter {
  connected = true;
  killed = false;
  command: DesktopActionProcessCommand | null = null;

  send(
    command: DesktopActionProcessCommand,
    callback?: (error: Error | null) => void,
  ) {
    this.command = command;
    callback?.(null);
    return true;
  }

  kill() {
    this.killed = true;
    queueMicrotask(() => this.emit('exit', null, 'SIGKILL'));
    return true;
  }

  respond(
    result: unknown,
    overrides: Partial<DesktopActionProcessResponse> = {},
  ) {
    if (!this.command) throw new Error('command was not sent');
    this.emit('message', {
      operationId: this.command.operationId,
      identity: this.command.identity,
      ok: true,
      result,
      ...overrides,
    });
  }

  exit(code = 0) {
    this.emit('exit', code, null);
  }
}

function harness(
  processTree?: DesktopProcessTreeController,
  surface:
    | 'local_computer'
    | 'remote_browser'
    | 'remote_computer' = 'local_computer',
) {
  const children: FakeChild[] = [];
  const forkChild: DesktopActionFork = vi.fn(() => {
    const child = new FakeChild();
    children.push(child);
    return child as never;
  });
  const create = () =>
    new IsolatedDesktopAction(
      identity,
      {
        surface,
        action: 'mouse.click',
        arguments: { x: 10, y: 20 },
        ...(surface === 'local_computer'
          ? { display: { width: 100, height: 100, scaleFactor: 1 } }
          : surface === 'remote_browser'
            ? { remoteBrowserCdpUrl: 'ws://remote.invalid/devtools' }
            : {
                remoteComputer: {
                  instanceId: 'remote-instance-1',
                  proxyUrl: 'https://remote.invalid/api/v1/proxy',
                  authHeaders: { Authorization: 'Bearer ephemeral' },
                  desktopControlToken: 'signed-control-token',
                },
              }),
      },
      forkChild,
      '/test/desktopActionWorker.js',
      processTree,
    );
  return { children, create };
}

describe('IsolatedDesktopAction', () => {
  it('passes only an explicit environment allowlist to the worker', () => {
    const environment = buildDesktopActionWorkerEnvironment({
      PATH: '/safe/bin',
      HOME: '/safe/home',
      AILLIUM_DESKTOP_AUTHORITY_PRIVATE_KEY: 'must-not-leak',
      OPENAI_API_KEY: 'must-not-leak',
      NODE_OPTIONS: '--require=unsafe.js',
    });

    expect(environment).toMatchObject({
      PATH: '/safe/bin',
      HOME: '/safe/home',
      ELECTRON_RUN_AS_NODE: '1',
      AILLIUM_DESKTOP_ACTION_PARENT_PID: String(process.pid),
    });
    expect(environment).not.toHaveProperty(
      'AILLIUM_DESKTOP_AUTHORITY_PRIVATE_KEY',
    );
    expect(environment).not.toHaveProperty('OPENAI_API_KEY');
    expect(environment).not.toHaveProperty('NODE_OPTIONS');
  });

  it('uses an isolated process group on POSIX and a fail-closed tree controller on Windows', () => {
    expect(createDesktopProcessTreeController('darwin').detached).toBe(true);
    expect(createDesktopProcessTreeController('linux').detached).toBe(true);
    expect(createDesktopProcessTreeController('win32').detached).toBe(false);
  });

  it.runIf(process.platform !== 'win32')(
    'force-terminates and verifies a real descendant process tree',
    async () => {
      const testDirectory = mkdtempSync(join(tmpdir(), 'aillium-tree-'));
      const heartbeatPath = join(testDirectory, 'heartbeat');
      let grandchildPid: number | null = null;
      const forkChild: DesktopActionFork = (modulePath, args, options) => {
        const child = fork(modulePath, args, options);
        child.once('message', (message: unknown) => {
          const candidate = message as { result?: { grandchildPid?: number } };
          grandchildPid = candidate.result?.grandchildPid ?? null;
        });
        return child;
      };
      const action = new IsolatedDesktopAction(
        identity,
        {
          surface: 'local_computer',
          action: 'screen.get_size',
          arguments: { heartbeatPath },
          display: { width: 100, height: 100, scaleFactor: 1 },
        },
        forkChild,
        join(__dirname, 'fixtures/blockingProcessTreeWorker.cjs'),
      );
      const running = action.run(new AbortController().signal);
      await vi.waitFor(() => expect(grandchildPid).not.toBeNull());
      await vi.waitFor(() =>
        expect(readFileSync(heartbeatPath, 'utf8').length).toBeGreaterThan(0),
      );

      action.terminate();
      await expect(running).rejects.toThrow('force-terminated');
      const stoppedLength = readFileSync(heartbeatPath, 'utf8').length;
      await new Promise((resolve) => setTimeout(resolve, 75));
      expect(readFileSync(heartbeatPath, 'utf8')).toHaveLength(stoppedLength);
      rmSync(testDirectory, { recursive: true, force: true });
    },
  );

  it('force-terminates a blocked child and proves process exit within 500ms', async () => {
    const h = harness();
    const action = h.create();
    const running = action.run(new AbortController().signal);
    await vi.waitFor(() => expect(h.children).toHaveLength(1));

    const startedAt = Date.now();
    action.terminate();

    await expect(running).rejects.toThrow('force-terminated');
    expect(Date.now() - startedAt).toBeLessThan(500);
    expect(h.children[0]?.killed).toBe(true);
  });

  it('ignores a late success message after force termination', async () => {
    const h = harness();
    const action = h.create();
    const running = action.run(new AbortController().signal);
    await vi.waitFor(() => expect(h.children).toHaveLength(1));
    const child = h.children[0]!;

    action.terminate();
    child.respond({ unsafeLateResult: true });

    await expect(running).rejects.toThrow('force-terminated');
  });

  it('does not accept an early success response when termination wins before exit', async () => {
    const h = harness();
    const action = h.create();
    const running = action.run(new AbortController().signal);
    await vi.waitFor(() => expect(h.children).toHaveLength(1));
    const child = h.children[0]!;

    child.respond({ unsafeEarlyResult: true });
    action.terminate();

    await expect(running).rejects.toThrow('force-terminated');
  });

  it('does not complete from a response until the owned child actually exits', async () => {
    const h = harness();
    const action = h.create();
    let completed = false;
    const running = action.run(new AbortController().signal).finally(() => {
      completed = true;
    });
    await vi.waitFor(() => expect(h.children).toHaveLength(1));
    const child = h.children[0]!;

    child.respond({ ok: true });
    await Promise.resolve();
    expect(completed).toBe(false);
    child.exit(0);

    await expect(running).resolves.toEqual({ ok: true });
  });

  it('rejects an orphaned pre-restart child and permits a fresh fenced action', async () => {
    const h = harness();
    const orphaned = h.create().run(new AbortController().signal);
    await vi.waitFor(() => expect(h.children).toHaveLength(1));
    h.children[0]!.exit(70);
    await expect(orphaned).rejects.toThrow('exited without proof');

    const restarted = h.create().run(new AbortController().signal);
    await vi.waitFor(() => expect(h.children).toHaveLength(2));
    h.children[1]!.respond({ recovered: true });
    h.children[1]!.exit(0);
    await expect(restarted).resolves.toEqual({ recovered: true });
  });

  it('never settles when whole-tree teardown cannot be proven', async () => {
    const processTree: DesktopProcessTreeController = {
      detached: false,
      terminate: async (child) => {
        child.kill('SIGKILL');
        return false;
      },
    };
    const h = harness(processTree);
    const action = h.create();
    let settled = false;
    void action
      .run(new AbortController().signal)
      .finally(() => {
        settled = true;
      })
      .catch(() => undefined);
    await vi.waitFor(() => expect(h.children).toHaveLength(1));

    action.terminate();
    await vi.waitFor(() => expect(h.children[0]?.killed).toBe(true));
    await Promise.resolve();

    expect(settled).toBe(false);
  });
});

describe('isolated remote-browser cancellation', () => {
  it('force-terminates a blocked remote browser inside 500ms', async () => {
    const h = harness(undefined, 'remote_browser');
    const action = h.create();
    const running = action.run(new AbortController().signal);
    await vi.waitFor(() => expect(h.children).toHaveLength(1));

    const startedAt = Date.now();
    action.terminate();

    await expect(running).rejects.toThrow('force-terminated');
    expect(Date.now() - startedAt).toBeLessThan(500);
  });

  it('rejects a remote-browser result delivered after force termination', async () => {
    const h = harness(undefined, 'remote_browser');
    const action = h.create();
    const running = action.run(new AbortController().signal);
    await vi.waitFor(() => expect(h.children).toHaveLength(1));

    action.terminate();
    h.children[0]!.respond({ unsafeRemoteLateResult: true });

    await expect(running).rejects.toThrow('force-terminated');
  });

  it('fences an orphaned remote-browser worker and permits a fresh restart', async () => {
    const h = harness(undefined, 'remote_browser');
    const orphaned = h.create().run(new AbortController().signal);
    await vi.waitFor(() => expect(h.children).toHaveLength(1));
    h.children[0]!.exit(70);
    await expect(orphaned).rejects.toThrow('exited without proof');

    const restarted = h.create().run(new AbortController().signal);
    await vi.waitFor(() => expect(h.children).toHaveLength(2));
    h.children[1]!.respond({ recoveredRemoteBrowser: true });
    h.children[1]!.exit(0);
    await expect(restarted).resolves.toEqual({ recoveredRemoteBrowser: true });
  });
});

describe('isolated remote-computer cancellation', () => {
  it('force-terminates a blocked MeshCentral worker inside 500ms', async () => {
    const h = harness(undefined, 'remote_computer');
    const action = h.create();
    const running = action.run(new AbortController().signal);
    await vi.waitFor(() => expect(h.children).toHaveLength(1));

    const startedAt = Date.now();
    action.terminate();

    await expect(running).rejects.toThrow('force-terminated');
    expect(Date.now() - startedAt).toBeLessThan(500);
  });

  it('rejects a MeshCentral result delivered after force termination', async () => {
    const h = harness(undefined, 'remote_computer');
    const action = h.create();
    const running = action.run(new AbortController().signal);
    await vi.waitFor(() => expect(h.children).toHaveLength(1));

    action.terminate();
    h.children[0]!.respond({ unsafeMeshLateResult: true });

    await expect(running).rejects.toThrow('force-terminated');
  });

  it('fences an orphaned MeshCentral worker and permits a fresh restart', async () => {
    const h = harness(undefined, 'remote_computer');
    const orphaned = h.create().run(new AbortController().signal);
    await vi.waitFor(() => expect(h.children).toHaveLength(1));
    h.children[0]!.exit(70);
    await expect(orphaned).rejects.toThrow('exited without proof');

    const restarted = h.create().run(new AbortController().signal);
    await vi.waitFor(() => expect(h.children).toHaveLength(2));
    h.children[1]!.respond({ recoveredMeshCentral: true });
    h.children[1]!.exit(0);
    await expect(restarted).resolves.toEqual({ recoveredMeshCentral: true });
  });

  it.runIf(process.platform !== 'win32')(
    'force-terminates a remote worker and its descendant process',
    async () => {
      const testDirectory = mkdtempSync(join(tmpdir(), 'aillium-mesh-tree-'));
      const heartbeatPath = join(testDirectory, 'heartbeat');
      let grandchildPid: number | null = null;
      const forkChild: DesktopActionFork = (modulePath, args, options) => {
        const child = fork(modulePath, args, options);
        child.once('message', (message: unknown) => {
          const candidate = message as { result?: { grandchildPid?: number } };
          grandchildPid = candidate.result?.grandchildPid ?? null;
        });
        return child;
      };
      const action = new IsolatedDesktopAction(
        identity,
        {
          surface: 'remote_computer',
          action: 'screen.get_size',
          arguments: { heartbeatPath },
          remoteComputer: {
            instanceId: 'remote-instance-1',
            proxyUrl: 'https://mesh-gateway.invalid',
            authHeaders: { Authorization: 'Bearer ephemeral' },
            desktopControlToken: 'signed-control-token',
          },
        },
        forkChild,
        join(__dirname, 'fixtures/blockingProcessTreeWorker.cjs'),
      );
      const running = action.run(new AbortController().signal);
      await vi.waitFor(() => expect(grandchildPid).not.toBeNull());
      await vi.waitFor(() =>
        expect(readFileSync(heartbeatPath, 'utf8').length).toBeGreaterThan(0),
      );

      const startedAt = Date.now();
      action.terminate();
      await expect(running).rejects.toThrow('force-terminated');
      const stoppedLength = readFileSync(heartbeatPath, 'utf8').length;
      await new Promise((resolve) => setTimeout(resolve, 75));
      expect(readFileSync(heartbeatPath, 'utf8')).toHaveLength(stoppedLength);
      expect(Date.now() - startedAt).toBeLessThan(500);
      rmSync(testDirectory, { recursive: true, force: true });
    },
  );

  it.runIf(
    process.platform !== 'win32' &&
      process.env.AILLIUM_ENABLE_LIVE_SOCKET_TEST === '1',
  )(
    'proves the owned remote transport socket is absent before settling',
    async () => {
      const testDirectory = mkdtempSync(join(tmpdir(), 'aillium-transport-'));
      const socketPath = join(testDirectory, 'mesh.sock');
      let socketConnected = false;
      let socketClosed = false;
      const server = createServer((socket) => {
        socketConnected = true;
        socket.once('close', () => {
          socketClosed = true;
        });
      });
      await new Promise<void>((resolve) =>
        server.listen(socketPath, () => resolve()),
      );
      const action = new IsolatedDesktopAction(
        identity,
        {
          surface: 'remote_computer',
          action: 'screen.get_size',
          arguments: { socketPath },
          remoteComputer: {
            instanceId: 'remote-instance-1',
            proxyUrl: 'http://127.0.0.1',
            authHeaders: { Authorization: 'Bearer ephemeral' },
            desktopControlToken: 'signed-control-token',
          },
        },
        fork,
        join(__dirname, 'fixtures/blockingRemoteTransportWorker.cjs'),
      );
      const running = action.run(new AbortController().signal);
      await vi.waitFor(() => expect(socketConnected).toBe(true));

      const startedAt = Date.now();
      action.terminate();
      await expect(running).rejects.toThrow('force-terminated');
      await vi.waitFor(() => expect(socketClosed).toBe(true));
      expect(Date.now() - startedAt).toBeLessThan(500);
      await new Promise<void>((resolve) => server.close(() => resolve()));
      rmSync(testDirectory, { recursive: true, force: true });
    },
  );
});
