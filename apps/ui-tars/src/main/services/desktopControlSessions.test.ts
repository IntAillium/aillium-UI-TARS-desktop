import { generateKeyPairSync } from 'node:crypto';
import { SignJWT } from 'jose';
import { importPKCS8 } from 'jose';
import { describe, expect, it, vi } from 'vitest';

import {
  assertDesktopControlTarget,
  DesktopControlSessionRegistry,
  readDesktopControlTarget,
  verifyDesktopControlToken,
  type DesktopControlIdentity,
} from './desktopControlSessions';

const AUTHORITY_KEYS = generateKeyPairSync('ed25519');
const PRIVATE_KEY_PEM = AUTHORITY_KEYS.privateKey.export({
  type: 'pkcs8',
  format: 'pem',
}) as string;
const PUBLIC_KEY_PEM = AUTHORITY_KEYS.publicKey.export({
  type: 'spki',
  format: 'pem',
}) as string;
const NOW_SECONDS = 1_800_000_000;

const identity = (
  overrides: Partial<DesktopControlIdentity> = {},
): DesktopControlIdentity => ({
  tenantId: 'tenant-1',
  workOrderId: 'work-order-1',
  authorityType: 'agent',
  authorityId: 'department-agent-1',
  runId: 'run-1',
  runStepId: 'run-step-1',
  desktopSessionId: 'desktop-session-1',
  attempt: 1,
  executorId: 'desktop-executor-1',
  fenceToken: '7',
  cancellationGeneration: 0,
  expiresAt: NOW_SECONDS + 300,
  ...overrides,
});

const executionContext = (value = identity()) => {
  const { expiresAt: _expiresAt, ...context } = value;
  return context;
};

function deferred<T = void>() {
  let resolve!: (value: T | PromiseLike<T>) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

async function signControlToken(
  claims: Record<string, unknown> = {},
  expiresAt = NOW_SECONDS + 300,
) {
  return new SignJWT({
    purpose: 'desktop-control',
    tenant_id: 'tenant-1',
    work_order_id: 'work-order-1',
    authority_type: 'agent',
    authority_id: 'department-agent-1',
    run_id: 'run-1',
    run_step_id: 'run-step-1',
    desktop_session_id: 'desktop-session-1',
    attempt: 1,
    executor_id: 'desktop-executor-1',
    fence_token: '7',
    cancellation_generation: 0,
    ...claims,
  })
    .setProtectedHeader({ alg: 'EdDSA' })
    .setIssuer('aillium-core')
    .setAudience('aillium-desktop')
    .setIssuedAt(NOW_SECONDS)
    .setExpirationTime(expiresAt)
    .sign(await importPKCS8(PRIVATE_KEY_PEM, 'EdDSA'));
}

describe('desktop control token scope', () => {
  it('binds tenant, work order, authority, run, attempt, executor, fence, cancellation generation, and expiry', async () => {
    // secretlint-disable-next-line @secretlint/secretlint-rule-pattern -- signed test fixture, not a credential
    const token = await signControlToken();
    await expect(
      verifyDesktopControlToken(token, PUBLIC_KEY_PEM, NOW_SECONDS),
    ).resolves.toEqual(identity());
  });

  it('rejects unscoped pairing, expired, and incomplete control tokens', async () => {
    const pairingToken = await signControlToken({ purpose: 'desktop-pairing' });
    const expiredToken = await signControlToken({}, NOW_SECONDS - 1);
    const missingFence = await signControlToken({ fence_token: undefined });

    await expect(
      verifyDesktopControlToken(pairingToken, PUBLIC_KEY_PEM, NOW_SECONDS),
    ).rejects.toMatchObject({ code: 'DESKTOP_CONTROL_SCOPE_INVALID' });
    await expect(
      verifyDesktopControlToken(expiredToken, PUBLIC_KEY_PEM, NOW_SECONDS),
    ).rejects.toMatchObject({ code: 'DESKTOP_CONTROL_TOKEN_INVALID' });
    await expect(
      verifyDesktopControlToken(missingFence, PUBLIC_KEY_PEM, NOW_SECONDS),
    ).rejects.toMatchObject({ code: 'DESKTOP_CONTROL_SCOPE_INVALID' });
  });

  it('does not let legacy environment flags turn a static token into authority', async () => {
    vi.stubEnv('AILLIUM_DESKTOP_BRIDGE_LEGACY_MODE', 'true');
    vi.stubEnv('AILLIUM_DESKTOP_BRIDGE_TOKEN', 'shared-static-token');

    await expect(
      verifyDesktopControlToken(
        'shared-static-token',
        PUBLIC_KEY_PEM,
        NOW_SECONDS,
      ),
    ).rejects.toMatchObject({ code: 'DESKTOP_CONTROL_TOKEN_INVALID' });

    vi.unstubAllEnvs();
  });
});

describe('desktop execution target fencing', () => {
  it('rejects a request targeting another run', () => {
    const target = readDesktopControlTarget({
      executionContext: { ...executionContext(), runId: 'run-2' },
    });
    expect(() => assertDesktopControlTarget(identity(), target)).toThrowError(
      expect.objectContaining({ code: 'DESKTOP_CONTROL_TARGET_MISMATCH' }),
    );
  });

  it('rejects a request targeting another work order', () => {
    const target = readDesktopControlTarget({
      executionContext: {
        ...executionContext(),
        workOrderId: 'work-order-other',
      },
    });
    expect(() => assertDesktopControlTarget(identity(), target)).toThrowError(
      expect.objectContaining({ code: 'DESKTOP_CONTROL_TARGET_MISMATCH' }),
    );
  });

  it('requires every authority, attempt, executor, fence, and generation field', () => {
    expect(() =>
      readDesktopControlTarget({
        executionContext: {
          runId: 'run-1',
          runStepId: 'run-step-1',
          desktopSessionId: 'desktop-session-1',
        },
      }),
    ).toThrowError(
      expect.objectContaining({ code: 'DESKTOP_CONTROL_TARGET_REQUIRED' }),
    );
  });

  it('rejects stale attempt, fence, and cancellation-generation authority', () => {
    const registry = new DesktopControlSessionRegistry(
      5_000,
      () => NOW_SECONDS * 1000,
    );
    const current = identity({
      attempt: 3,
      fenceToken: '12',
      cancellationGeneration: 2,
    });
    registry.ensure(current);

    for (const stale of [
      identity({ attempt: 2, fenceToken: '12', cancellationGeneration: 2 }),
      identity({ attempt: 3, fenceToken: '11', cancellationGeneration: 2 }),
      identity({ attempt: 3, fenceToken: '12', cancellationGeneration: 1 }),
    ]) {
      expect(() => registry.ensure(stale)).toThrowError(
        expect.objectContaining({ code: 'DESKTOP_CONTROL_STALE_AUTHORITY' }),
      );
    }
  });
});

describe('desktop session cancellation and isolation', () => {
  it('stopping one session does not stop or fence another owned action', async () => {
    const registry = new DesktopControlSessionRegistry(
      5_000,
      () => NOW_SECONDS * 1000,
    );
    const sessionA = identity();
    const sessionB = identity({
      runId: 'run-2',
      runStepId: 'run-step-2',
      desktopSessionId: 'desktop-session-2',
    });
    const actionA = deferred();
    const stopA = vi.fn();
    const runningA = registry.runOwnedAction(sessionA, () => actionA.promise, {
      cooperativeStop: stopA,
    });
    registry.ensure(sessionB);

    expect(() =>
      registry.runOwnedAction(sessionB, async () => undefined),
    ).toThrowError(expect.objectContaining({ code: 'DESKTOP_RUNTIME_BUSY' }));
    const acknowledgement = await registry.stop(sessionB);

    expect(acknowledgement).toMatchObject({
      runId: 'run-2',
      desktopSessionId: 'desktop-session-2',
      state: 'stopped',
      verified: true,
    });
    expect(stopA).not.toHaveBeenCalled();
    expect(registry.getState(sessionA)).toBe('active');
    actionA.resolve();
    await runningA;
  });

  it('rejects all input after a verified stop', async () => {
    const registry = new DesktopControlSessionRegistry(
      5_000,
      () => NOW_SECONDS * 1000,
    );
    const session = identity();
    registry.ensure(session);
    await registry.stop(session);

    expect(() => registry.assertAcceptsInput(session)).toThrowError(
      expect.objectContaining({ code: 'DESKTOP_SESSION_STOPPED' }),
    );
    await expect(registry.resume(session)).rejects.toMatchObject({
      code: 'DESKTOP_SESSION_STOPPED',
    });
  });

  it('returns a cooperative acknowledgement only after the real action promise ends', async () => {
    const registry = new DesktopControlSessionRegistry();
    const session = identity({
      expiresAt: Math.floor(Date.now() / 1000) + 60,
    });
    const action = deferred();
    const cooperativeStop = vi.fn(() => action.resolve());
    const running = registry.runOwnedAction(session, () => action.promise, {
      cooperativeStop,
    });
    const stopAuthority = {
      ...session,
      fenceToken: '8',
      cancellationGeneration: 1,
    };

    const acknowledgement = await registry.stop(stopAuthority);
    await running;

    expect(cooperativeStop).toHaveBeenCalledTimes(1);
    expect(acknowledgement).toMatchObject({
      state: 'stopped',
      cooperative: true,
      forced: false,
      verified: true,
      fenceToken: '8',
      cancellationGeneration: 1,
    });
    await expect(registry.stop(stopAuthority)).resolves.toEqual(
      acknowledgement,
    );
  });

  it('does not claim verified teardown while a direct action promise is alive', async () => {
    const registry = new DesktopControlSessionRegistry(20);
    const session = identity({
      expiresAt: Math.floor(Date.now() / 1000) + 60,
    });
    const action = deferred();
    const forceStop = vi.fn();
    const running = registry.runOwnedAction(session, () => action.promise, {
      forceStop,
    });

    await expect(registry.stop(session)).rejects.toMatchObject({
      code: 'DESKTOP_TEARDOWN_UNVERIFIED',
    });
    expect(forceStop).toHaveBeenCalledTimes(1);
    expect(registry.getState(session)).toBe('stopping');
    expect(registry.hasActiveOperation(session)).toBe(true);

    action.resolve();
    await running;
    await expect(registry.stop(session)).resolves.toMatchObject({
      state: 'stopped',
      verified: true,
    });
  });

  it('returns a forced acknowledgement when force termination ends the real promise', async () => {
    const registry = new DesktopControlSessionRegistry(20);
    const session = identity({
      expiresAt: Math.floor(Date.now() / 1000) + 60,
    });
    const action = deferred();
    const forceStop = vi.fn(() => action.resolve());
    const running = registry.runOwnedAction(session, () => action.promise, {
      cooperativeStop: () => new Promise<void>(() => undefined),
      forceStop,
    });

    const acknowledgement = await registry.stop(session);
    await running;

    expect(forceStop).toHaveBeenCalledTimes(1);
    expect(acknowledgement).toMatchObject({
      state: 'stopped',
      cooperative: false,
      forced: true,
      verified: true,
    });
  });

  it('requires a correlated remote fence cancellation before verified teardown', async () => {
    const registry = new DesktopControlSessionRegistry(500);
    const session = identity({
      expiresAt: Math.floor(Date.now() / 1000) + 60,
    });
    const stopAuthority = { ...session, cancellationGeneration: 1 };
    const action = deferred();
    const cancelFence = vi.fn(async () => ({ operationId: 'cancel-op-1' }));
    const running = registry.runOwnedAction(session, () => action.promise, {
      cancelFence,
      cooperativeStop: () => action.resolve(),
    });

    const acknowledgement = await registry.stop(stopAuthority, {
      desktopControlToken: 'signed-new-generation-token',
    });
    await running;

    expect(cancelFence).toHaveBeenCalledWith(
      stopAuthority,
      'signed-new-generation-token',
      expect.any(AbortSignal),
    );
    expect(acknowledgement).toMatchObject({
      state: 'stopped',
      verified: true,
      cancellationGeneration: 1,
      remoteCancellationOperationId: 'cancel-op-1',
    });
  });

  it('retains remote cancellation authority after the action completes normally', async () => {
    const registry = new DesktopControlSessionRegistry(500);
    const session = identity({
      expiresAt: Math.floor(Date.now() / 1000) + 60,
    });
    const stopAuthority = { ...session, cancellationGeneration: 1 };
    const cancelFence = vi.fn(async () => ({
      operationId: 'cancel-after-completion',
    }));
    await registry.runOwnedAction(session, async () => 'completed', {
      cancelFence,
    });
    expect(registry.hasActiveOperation(session)).toBe(false);

    await expect(
      registry.stop(stopAuthority, {
        desktopControlToken: 'signed-new-generation-token',
      }),
    ).resolves.toMatchObject({
      verified: true,
      remoteCancellationOperationId: 'cancel-after-completion',
    });
    expect(cancelFence).toHaveBeenCalledTimes(1);
  });

  it('kills locally but fails closed and retains an idempotent retry when remote cancellation proof is unavailable', async () => {
    const registry = new DesktopControlSessionRegistry(500);
    const session = identity({
      expiresAt: Math.floor(Date.now() / 1000) + 60,
    });
    const stopAuthority = { ...session, cancellationGeneration: 1 };
    const action = deferred();
    const cancelFence = vi
      .fn()
      .mockRejectedValueOnce(new Error('gateway unavailable'))
      .mockResolvedValueOnce({ operationId: 'cancel-op-retried' });
    const forceStop = vi.fn(() => action.resolve());
    const running = registry.runOwnedAction(session, () => action.promise, {
      cancelFence,
      forceStop,
    });

    await expect(
      registry.stop(stopAuthority, {
        force: true,
        desktopControlToken: 'signed-new-generation-token',
      }),
    ).rejects.toMatchObject({ code: 'DESKTOP_REMOTE_CANCEL_UNVERIFIED' });
    await running;
    expect(forceStop).toHaveBeenCalledTimes(1);
    expect(registry.getState(stopAuthority)).toBe('stopping');

    await expect(
      registry.stop(stopAuthority, {
        desktopControlToken: 'signed-new-generation-token',
      }),
    ).resolves.toMatchObject({
      verified: true,
      remoteCancellationOperationId: 'cancel-op-retried',
    });
    expect(cancelFence).toHaveBeenCalledTimes(2);
  });

  it('starts force teardown immediately and shares one deadline with a hung remote cancellation', async () => {
    const registry = new DesktopControlSessionRegistry(100);
    const session = identity({
      expiresAt: Math.floor(Date.now() / 1000) + 60,
    });
    const stopAuthority = { ...session, cancellationGeneration: 1 };
    const action = deferred();
    const cancelFence = vi.fn(() => new Promise<null>(() => undefined));
    const forceStop = vi.fn(() => action.resolve());
    const running = registry.runOwnedAction(session, () => action.promise, {
      cancelFence,
      forceStop,
    });

    const startedAt = Date.now();
    const stopping = registry.stop(stopAuthority, {
      force: true,
      deadlineMs: 100,
      desktopControlToken: 'signed-new-generation-token',
    });

    expect(forceStop).toHaveBeenCalledTimes(1);
    await expect(stopping).rejects.toMatchObject({
      code: 'DESKTOP_REMOTE_CANCEL_UNVERIFIED',
    });
    expect(Date.now() - startedAt).toBeLessThan(500);
    await running;
    expect(cancelFence).toHaveBeenCalledTimes(1);
    expect(registry.getState(stopAuthority)).toBe('stopping');
  });

  it('invokes explicit force immediately and never reports before the action settles', async () => {
    const registry = new DesktopControlSessionRegistry(5_000);
    const session = identity({
      expiresAt: Math.floor(Date.now() / 1000) + 60,
    });
    const action = deferred();
    const cooperativeStop = vi.fn();
    const forceStop = vi.fn(() => action.resolve());
    const running = registry.runOwnedAction(session, () => action.promise, {
      cooperativeStop,
      forceStop,
    });

    const acknowledgement = await registry.stop(session, {
      force: true,
      deadlineMs: 500,
    });
    await running;

    expect(cooperativeStop).not.toHaveBeenCalled();
    expect(forceStop).toHaveBeenCalledTimes(1);
    expect(acknowledgement).toMatchObject({
      state: 'stopped',
      forced: true,
      verified: true,
    });
  });

  it('keeps a cooperative-only stop unverified when its action misses the caller deadline', async () => {
    const registry = new DesktopControlSessionRegistry(5_000);
    const session = identity({
      expiresAt: Math.floor(Date.now() / 1000) + 60,
    });
    const action = deferred();
    const forceStop = vi.fn();
    const running = registry.runOwnedAction(session, () => action.promise, {
      cooperativeStop: vi.fn(),
      forceStop,
    });

    await expect(
      registry.stop(session, { force: false, deadlineMs: 20 }),
    ).rejects.toMatchObject({ code: 'DESKTOP_TEARDOWN_UNVERIFIED' });
    expect(forceStop).not.toHaveBeenCalled();

    action.resolve();
    await running;
  });

  it('releases ownership after token expiry when the started action finishes', async () => {
    let nowMs = NOW_SECONDS * 1000;
    const registry = new DesktopControlSessionRegistry(5_000, () => nowMs);
    const expiring = identity({ expiresAt: NOW_SECONDS + 1 });
    const action = deferred();
    const running = registry.runOwnedAction(expiring, () => action.promise);

    nowMs += 2_000;
    action.resolve();
    await running;

    expect(registry.hasActiveOperation(expiring)).toBe(false);
    const replacement = identity({
      runId: 'run-2',
      runStepId: 'run-step-2',
      desktopSessionId: 'desktop-session-2',
      expiresAt: NOW_SECONDS + 30,
    });
    await expect(
      registry.runOwnedAction(replacement, async () => 'ok'),
    ).resolves.toBe('ok');
  });
});
