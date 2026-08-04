import type { JWTPayload } from 'jose';
import { importSPKI, jwtVerify } from 'jose';

export type DesktopAuthorityType = 'user' | 'agent';

export type DesktopControlIdentity = {
  tenantId: string;
  workOrderId: string;
  authorityType: DesktopAuthorityType;
  authorityId: string;
  runId: string;
  runStepId: string;
  desktopSessionId: string;
  attempt: number;
  executorId: string;
  fenceToken: string;
  cancellationGeneration: number;
  expiresAt: number;
};

export type DesktopControlTarget = Omit<DesktopControlIdentity, 'expiresAt'>;
export type DesktopSessionState = 'active' | 'paused' | 'stopping' | 'stopped';

export type DesktopTeardownAcknowledgement = DesktopControlTarget & {
  state: 'stopped';
  acknowledgedAt: string;
  cooperative: boolean;
  forced: boolean;
  verified: true;
  remoteCancellationOperationId: string | null;
};

export class DesktopControlError extends Error {
  constructor(
    message: string,
    public readonly code: string,
    public readonly statusCode: number,
  ) {
    super(message);
    this.name = 'DesktopControlError';
  }
}

export type DesktopOperationControls = {
  pause?: () => void | Promise<void>;
  resume?: () => void | Promise<void>;
  cooperativeStop?: (signal: AbortSignal) => void | Promise<void>;
  forceStop?: () => void | Promise<void>;
  cancelFence?: (
    identity: DesktopControlIdentity,
    desktopControlToken: string,
    signal: AbortSignal,
  ) => Promise<{ operationId?: unknown } | null>;
};

type ActiveDesktopOperation = {
  abortController: AbortController;
  controls: DesktopOperationControls;
  completion: Promise<void>;
  settled: boolean;
};

type DesktopSession = {
  identity: DesktopControlIdentity;
  state: DesktopSessionState;
  activeOperation: ActiveDesktopOperation | null;
  teardownAcknowledgement: DesktopTeardownAcknowledgement | null;
  pendingFenceCancellation: DesktopOperationControls['cancelFence'] | null;
};

const FENCE_TOKEN_PATTERN = /^(0|[1-9]\d*)$/;

function readClaim(payload: JWTPayload, ...names: string[]) {
  for (const name of names) {
    const value = payload[name];
    if (typeof value === 'string' && value.trim()) return value.trim();
  }
  return null;
}

function readIntegerClaim(payload: JWTPayload, ...names: string[]) {
  for (const name of names) {
    const value = payload[name];
    if (typeof value === 'number' && Number.isInteger(value)) return value;
  }
  return null;
}

function requireClaim(payload: JWTPayload, label: string, ...names: string[]) {
  const value = readClaim(payload, ...names);
  if (!value) {
    throw new DesktopControlError(
      `Desktop control token is missing ${label}`,
      'DESKTOP_CONTROL_SCOPE_INVALID',
      401,
    );
  }
  return value;
}

function requirePositiveIntegerClaim(
  payload: JWTPayload,
  label: string,
  ...names: string[]
) {
  const value = readIntegerClaim(payload, ...names);
  if (value === null || value < 1) {
    throw new DesktopControlError(
      `Desktop control token has an invalid ${label}`,
      'DESKTOP_CONTROL_SCOPE_INVALID',
      401,
    );
  }
  return value;
}

function requireNonnegativeIntegerClaim(
  payload: JWTPayload,
  label: string,
  ...names: string[]
) {
  const value = readIntegerClaim(payload, ...names);
  if (value === null || value < 0) {
    throw new DesktopControlError(
      `Desktop control token has an invalid ${label}`,
      'DESKTOP_CONTROL_SCOPE_INVALID',
      401,
    );
  }
  return value;
}

export function parseDesktopControlIdentity(
  payload: JWTPayload,
  nowSeconds = Math.floor(Date.now() / 1000),
): DesktopControlIdentity {
  if (payload.purpose !== 'desktop-control') {
    throw new DesktopControlError(
      'Desktop control token purpose is invalid',
      'DESKTOP_CONTROL_SCOPE_INVALID',
      401,
    );
  }
  if (typeof payload.exp !== 'number' || payload.exp <= nowSeconds) {
    throw new DesktopControlError(
      'Desktop control token is expired or has no expiry',
      'DESKTOP_CONTROL_TOKEN_EXPIRED',
      401,
    );
  }

  const authorityType = requireClaim(
    payload,
    'authority type',
    'authority_type',
    'authorityType',
  );
  if (authorityType !== 'user' && authorityType !== 'agent') {
    throw new DesktopControlError(
      'Desktop control authority type must be user or agent',
      'DESKTOP_CONTROL_SCOPE_INVALID',
      401,
    );
  }
  const fenceToken = requireClaim(
    payload,
    'fence token',
    'fence_token',
    'fenceToken',
  );
  if (!FENCE_TOKEN_PATTERN.test(fenceToken)) {
    throw new DesktopControlError(
      'Desktop control fence token must be an unsigned integer string',
      'DESKTOP_CONTROL_SCOPE_INVALID',
      401,
    );
  }

  return {
    tenantId: requireClaim(payload, 'tenant identity', 'tenant_id', 'tenantId'),
    workOrderId: requireClaim(
      payload,
      'work-order identity',
      'work_order_id',
      'workOrderId',
    ),
    authorityType,
    authorityId: requireClaim(
      payload,
      'authority identity',
      'authority_id',
      'authorityId',
    ),
    runId: requireClaim(payload, 'run identity', 'run_id', 'runId'),
    runStepId: requireClaim(
      payload,
      'run-step identity',
      'run_step_id',
      'runStepId',
    ),
    desktopSessionId: requireClaim(
      payload,
      'desktop-session identity',
      'desktop_session_id',
      'desktopSessionId',
    ),
    attempt: requirePositiveIntegerClaim(payload, 'attempt', 'attempt'),
    executorId: requireClaim(
      payload,
      'executor identity',
      'executor_id',
      'executorId',
    ),
    fenceToken,
    cancellationGeneration: requireNonnegativeIntegerClaim(
      payload,
      'cancellation generation',
      'cancellation_generation',
      'cancellationGeneration',
    ),
    expiresAt: payload.exp,
  };
}

export async function verifyDesktopControlToken(
  // secretlint-disable-next-line @secretlint/secretlint-rule-pattern -- runtime bearer value, not an embedded secret
  token: string,
  publicKeyPem: string,
  nowSeconds = Math.floor(Date.now() / 1000),
) {
  try {
    const publicKey = await importSPKI(publicKeyPem, 'EdDSA');
    const { payload } = await jwtVerify(token, publicKey, {
      algorithms: ['EdDSA'],
      audience: 'aillium-desktop',
      issuer: 'aillium-core',
      currentDate: new Date(nowSeconds * 1000),
    });
    return parseDesktopControlIdentity(payload, nowSeconds);
  } catch (error) {
    if (error instanceof DesktopControlError) throw error;
    throw new DesktopControlError(
      'Desktop control token is invalid',
      'DESKTOP_CONTROL_TOKEN_INVALID',
      401,
    );
  }
}

function readTargetValue(source: Record<string, unknown>, ...names: string[]) {
  for (const name of names) {
    const value = source[name];
    if (typeof value === 'string' && value.trim()) return value.trim();
  }
  return null;
}

function readTargetInteger(
  source: Record<string, unknown>,
  ...names: string[]
) {
  for (const name of names) {
    const value = source[name];
    if (typeof value === 'number' && Number.isInteger(value)) return value;
  }
  return null;
}

export function readDesktopControlTarget(
  body: Record<string, unknown>,
): DesktopControlTarget {
  const nested =
    body.executionContext &&
    typeof body.executionContext === 'object' &&
    !Array.isArray(body.executionContext)
      ? (body.executionContext as Record<string, unknown>)
      : body;
  const target = {
    tenantId: readTargetValue(nested, 'tenantId', 'tenant_id'),
    workOrderId: readTargetValue(nested, 'workOrderId', 'work_order_id'),
    authorityType: readTargetValue(nested, 'authorityType', 'authority_type'),
    authorityId: readTargetValue(nested, 'authorityId', 'authority_id'),
    runId: readTargetValue(nested, 'runId', 'run_id'),
    runStepId: readTargetValue(nested, 'runStepId', 'run_step_id'),
    desktopSessionId: readTargetValue(
      nested,
      'desktopSessionId',
      'desktop_session_id',
    ),
    attempt: readTargetInteger(nested, 'attempt'),
    executorId: readTargetValue(nested, 'executorId', 'executor_id'),
    fenceToken: readTargetValue(nested, 'fenceToken', 'fence_token'),
    cancellationGeneration: readTargetInteger(
      nested,
      'cancellationGeneration',
      'cancellation_generation',
    ),
  };
  if (
    !target.tenantId ||
    !target.workOrderId ||
    (target.authorityType !== 'user' && target.authorityType !== 'agent') ||
    !target.authorityId ||
    !target.runId ||
    !target.runStepId ||
    !target.desktopSessionId ||
    target.attempt === null ||
    target.attempt < 1 ||
    !target.executorId ||
    !target.fenceToken ||
    !FENCE_TOKEN_PATTERN.test(target.fenceToken) ||
    target.cancellationGeneration === null ||
    target.cancellationGeneration < 0
  ) {
    throw new DesktopControlError(
      'A complete fenced desktop executionContext is required',
      'DESKTOP_CONTROL_TARGET_REQUIRED',
      400,
    );
  }
  return target as DesktopControlTarget;
}

export function assertDesktopControlTarget(
  identity: DesktopControlIdentity,
  target: DesktopControlTarget,
) {
  const fields: (keyof DesktopControlTarget)[] = [
    'tenantId',
    'workOrderId',
    'authorityType',
    'authorityId',
    'runId',
    'runStepId',
    'desktopSessionId',
    'attempt',
    'executorId',
    'fenceToken',
    'cancellationGeneration',
  ];
  const mismatch = fields.find((field) => identity[field] !== target[field]);
  if (mismatch) {
    throw new DesktopControlError(
      `Desktop control target does not match token scope (${mismatch})`,
      'DESKTOP_CONTROL_TARGET_MISMATCH',
      403,
    );
  }
}

function sameLineage(
  left: DesktopControlIdentity,
  right: DesktopControlIdentity,
) {
  return (
    left.tenantId === right.tenantId &&
    left.workOrderId === right.workOrderId &&
    left.authorityType === right.authorityType &&
    left.authorityId === right.authorityId &&
    left.runId === right.runId &&
    left.runStepId === right.runStepId &&
    left.desktopSessionId === right.desktopSessionId
  );
}

function sameAuthorityVersion(
  left: DesktopControlIdentity,
  right: DesktopControlIdentity,
) {
  return (
    sameLineage(left, right) &&
    left.attempt === right.attempt &&
    left.executorId === right.executorId &&
    left.fenceToken === right.fenceToken &&
    left.cancellationGeneration === right.cancellationGeneration
  );
}

function isStaleAuthority(
  incoming: DesktopControlIdentity,
  current: DesktopControlIdentity,
) {
  return (
    incoming.attempt < current.attempt ||
    BigInt(incoming.fenceToken) < BigInt(current.fenceToken) ||
    incoming.cancellationGeneration < current.cancellationGeneration
  );
}

function targetFromIdentity(
  identity: DesktopControlIdentity,
): DesktopControlTarget {
  const { expiresAt: _expiresAt, ...target } = identity;
  return target;
}

function waitForCompletion(completion: Promise<void>, timeoutMs: number) {
  if (timeoutMs <= 0) return Promise.resolve(false);
  let timer: ReturnType<typeof setTimeout> | null = null;
  const timeout = new Promise<boolean>((resolve) => {
    timer = setTimeout(() => resolve(false), timeoutMs);
  });
  return Promise.race([completion.then(() => true), timeout]).finally(() => {
    if (timer) clearTimeout(timer);
  });
}

type SettledOutcome<T> =
  | { settled: true; value: T }
  | { settled: false; value?: never };

function waitForOutcome<T>(
  outcome: Promise<T>,
  timeoutMs: number,
): Promise<SettledOutcome<T>> {
  if (timeoutMs <= 0) return Promise.resolve({ settled: false });
  let timer: ReturnType<typeof setTimeout> | null = null;
  const timeout = new Promise<SettledOutcome<T>>((resolve) => {
    timer = setTimeout(() => resolve({ settled: false }), timeoutMs);
  });
  return Promise.race([
    outcome.then((value) => ({ settled: true, value }) as const),
    timeout,
  ]).finally(() => {
    if (timer) clearTimeout(timer);
  });
}

function invokeBestEffort(action: (() => void | Promise<void>) | undefined) {
  try {
    void Promise.resolve(action?.()).catch(() => undefined);
  } catch {
    // Completion of the owned action, not the callback return value, is the
    // teardown proof. A broken callback must not bypass the hard deadline.
  }
}

export class DesktopControlSessionRegistry {
  private readonly sessions = new Map<string, DesktopSession>();
  private runtimeOwnerSessionId: string | null = null;

  constructor(
    private readonly forcedStopDeadlineMs = 5_000,
    private readonly now = () => Date.now(),
  ) {}

  private resolveSession(
    identity: DesktopControlIdentity,
    requireFresh: boolean,
    allowActiveAuthorityUpgrade = false,
  ) {
    if (requireFresh && identity.expiresAt * 1000 <= this.now()) {
      throw new DesktopControlError(
        'Desktop control authority has expired',
        'DESKTOP_CONTROL_TOKEN_EXPIRED',
        401,
      );
    }
    const existing = this.sessions.get(identity.desktopSessionId);
    if (!existing) return null;
    if (!sameLineage(existing.identity, identity)) {
      throw new DesktopControlError(
        'Desktop session identity is already bound to another run or authority',
        'DESKTOP_SESSION_SCOPE_MISMATCH',
        403,
      );
    }
    if (isStaleAuthority(identity, existing.identity)) {
      throw new DesktopControlError(
        'Desktop control authority is stale',
        'DESKTOP_CONTROL_STALE_AUTHORITY',
        409,
      );
    }
    if (!sameAuthorityVersion(existing.identity, identity)) {
      if (existing.activeOperation && !allowActiveAuthorityUpgrade) {
        throw new DesktopControlError(
          'Desktop authority cannot change while an action is in flight',
          'DESKTOP_CONTROL_AUTHORITY_CONFLICT',
          409,
        );
      }
      existing.identity = identity;
    }
    return existing;
  }

  ensure(identity: DesktopControlIdentity) {
    const existing = this.resolveSession(identity, true);
    if (existing) return existing;
    const session: DesktopSession = {
      identity,
      state: 'active',
      activeOperation: null,
      teardownAcknowledgement: null,
      pendingFenceCancellation: null,
    };
    this.sessions.set(identity.desktopSessionId, session);
    return session;
  }

  private ensureForControl(identity: DesktopControlIdentity) {
    const existing = this.resolveSession(identity, true, true);
    if (existing) return existing;
    return this.ensure(identity);
  }

  assertAcceptsInput(identity: DesktopControlIdentity) {
    const session = this.ensure(identity);
    if (session.state === 'stopped' || session.state === 'stopping') {
      throw new DesktopControlError(
        'Desktop session is stopped; post-stop input is fenced',
        'DESKTOP_SESSION_STOPPED',
        409,
      );
    }
    if (session.state === 'paused') {
      throw new DesktopControlError(
        'Desktop session is paused',
        'DESKTOP_SESSION_PAUSED',
        409,
      );
    }
  }

  runOwnedAction<T>(
    identity: DesktopControlIdentity,
    execute: (signal: AbortSignal) => Promise<T>,
    controls: DesktopOperationControls = {},
  ): Promise<T> {
    this.assertAcceptsInput(identity);
    if (this.runtimeOwnerSessionId) {
      throw new DesktopControlError(
        'The local desktop runtime is already owned by another action',
        'DESKTOP_RUNTIME_BUSY',
        409,
      );
    }
    const session = this.ensure(identity);
    const abortController = new AbortController();
    const operation: ActiveDesktopOperation = {
      abortController,
      controls,
      completion: Promise.resolve(),
      settled: false,
    };
    session.activeOperation = operation;
    if (controls.cancelFence) {
      // A completed remote effect still leaves gateway lineage authority
      // current. Retain the signed cancellation capability until a newer
      // cancellation is durably acknowledged, rather than losing it when the
      // child process exits normally.
      session.pendingFenceCancellation = controls.cancelFence;
    }
    this.runtimeOwnerSessionId = identity.desktopSessionId;

    const result = Promise.resolve().then(() =>
      execute(abortController.signal),
    );
    const trackedResult = result.finally(() => {
      operation.settled = true;
      this.releaseRuntime(identity, operation);
    });
    operation.completion = trackedResult.then(
      () => undefined,
      () => undefined,
    );
    return trackedResult;
  }

  releaseRuntime(
    identity: DesktopControlIdentity,
    expectedOperation?: ActiveDesktopOperation,
  ) {
    // Cleanup is deliberately expiry-insensitive. Expiry prevents new control
    // actions, but must never strand ownership held by an action that started
    // while its authority was valid.
    const session = this.sessions.get(identity.desktopSessionId);
    if (!session) return;
    if (!sameLineage(session.identity, identity)) {
      throw new DesktopControlError(
        'Desktop cleanup identity does not match the owned session',
        'DESKTOP_SESSION_SCOPE_MISMATCH',
        403,
      );
    }
    if (expectedOperation && session.activeOperation !== expectedOperation)
      return;
    session.activeOperation = null;
    if (this.runtimeOwnerSessionId === identity.desktopSessionId) {
      this.runtimeOwnerSessionId = null;
    }
  }

  async pause(identity: DesktopControlIdentity) {
    const session = this.ensureForControl(identity);
    if (session.state === 'stopped' || session.state === 'stopping') {
      this.assertAcceptsInput(identity);
    }
    if (session.state === 'paused') return { state: 'paused' as const };
    await session.activeOperation?.controls.pause?.();
    session.state = 'paused';
    return { state: 'paused' as const };
  }

  async resume(identity: DesktopControlIdentity) {
    const session = this.ensureForControl(identity);
    if (session.state === 'stopped' || session.state === 'stopping') {
      this.assertAcceptsInput(identity);
    }
    if (session.state === 'active') return { state: 'active' as const };
    await session.activeOperation?.controls.resume?.();
    session.state = 'active';
    return { state: 'active' as const };
  }

  async stop(
    identity: DesktopControlIdentity,
    options: {
      force?: boolean;
      deadlineMs?: number;
      desktopControlToken?: string;
    } = {},
  ): Promise<DesktopTeardownAcknowledgement> {
    const session = this.ensureForControl(identity);
    if (session.teardownAcknowledgement) return session.teardownAcknowledgement;
    session.state = 'stopping';
    const operation = session.activeOperation;
    let forced = false;
    let cooperative = true;
    let remoteCancellationOperationId: string | null = null;
    let remoteCancellationError: unknown = null;
    const requestedDeadlineMs = Math.min(
      this.forcedStopDeadlineMs,
      Math.max(1, options.deadlineMs ?? this.forcedStopDeadlineMs),
    );
    const deadlineAt = Date.now() + requestedDeadlineMs;
    const remainingDeadlineMs = () => Math.max(0, deadlineAt - Date.now());
    const cancelFence =
      operation?.controls.cancelFence ?? session.pendingFenceCancellation;
    const cancellationAbort = new AbortController();
    const cancellationDeadline = setTimeout(
      () =>
        cancellationAbort.abort(
          new DesktopControlError(
            'Remote cancellation acknowledgement timed out',
            'DESKTOP_REMOTE_CANCEL_UNVERIFIED',
            503,
          ),
        ),
      requestedDeadlineMs,
    );

    const cancellationAttempt = Promise.resolve().then(async () => {
      if (!cancelFence) return null;
      if (!options.desktopControlToken) {
        throw new DesktopControlError(
          'Signed desktop-control cancellation authority is required',
          'DESKTOP_REMOTE_CANCEL_UNVERIFIED',
          503,
        );
      }
      const proof = await cancelFence(
        identity,
        options.desktopControlToken,
        cancellationAbort.signal,
      );
      const operationId =
        proof && typeof proof.operationId === 'string'
          ? proof.operationId
          : null;
      if (proof !== null && !operationId) {
        throw new DesktopControlError(
          'Remote cancellation did not return a correlated operation identity',
          'DESKTOP_REMOTE_CANCEL_UNVERIFIED',
          503,
        );
      }
      return operationId;
    });
    const cancellationOutcome = cancellationAttempt.then(
      (operationId) => ({ ok: true as const, operationId }),
      (error: unknown) => ({ ok: false as const, error }),
    );

    const localTeardown = (async () => {
      if (!operation || operation.settled) return true;
      operation.abortController.abort(
        new DesktopControlError(
          'Desktop session stop requested',
          'DESKTOP_SESSION_STOPPED',
          409,
        ),
      );
      if (options.force === true) {
        forced = true;
        cooperative = false;
        invokeBestEffort(operation.controls.forceStop);
        return waitForCompletion(operation.completion, remainingDeadlineMs());
      }

      invokeBestEffort(() =>
        operation.controls.cooperativeStop?.(operation.abortController.signal),
      );
      const forceGraceMs = Math.min(
        250,
        Math.max(1, Math.floor(requestedDeadlineMs / 2)),
      );
      const cooperativeDeadlineMs =
        options.force === false
          ? remainingDeadlineMs()
          : Math.max(0, remainingDeadlineMs() - forceGraceMs);
      let completed = await waitForCompletion(
        operation.completion,
        cooperativeDeadlineMs,
      );
      if (!completed && options.force === undefined) {
        forced = true;
        cooperative = false;
        invokeBestEffort(operation.controls.forceStop);
        completed = await waitForCompletion(
          operation.completion,
          remainingDeadlineMs(),
        );
      }
      return completed;
    })();

    const cancellationWithinDeadline = waitForOutcome(
      cancellationOutcome,
      remainingDeadlineMs(),
    );
    const [completed, cancellationResult] = await Promise.all([
      localTeardown,
      cancellationWithinDeadline,
    ]).finally(() => {
      clearTimeout(cancellationDeadline);
      if (!cancellationAbort.signal.aborted) {
        cancellationAbort.abort(
          new DesktopControlError(
            'Desktop session teardown completed',
            'DESKTOP_SESSION_STOPPED',
            409,
          ),
        );
      }
    });

    if (operation && (!completed || !operation.settled)) {
      throw new DesktopControlError(
        'Desktop action is still running; teardown is not verified',
        'DESKTOP_TEARDOWN_UNVERIFIED',
        503,
      );
    }

    if (!cancellationResult.settled) {
      remoteCancellationError = new DesktopControlError(
        'Remote cancellation acknowledgement timed out',
        'DESKTOP_REMOTE_CANCEL_UNVERIFIED',
        503,
      );
    } else if (!cancellationResult.value.ok) {
      remoteCancellationError = cancellationResult.value.error;
    } else {
      remoteCancellationOperationId = cancellationResult.value.operationId;
    }

    if (cancelFence) {
      session.pendingFenceCancellation = remoteCancellationError
        ? cancelFence
        : null;
    }

    if (remoteCancellationError) {
      throw new DesktopControlError(
        `Remote cancellation is not durably verified: ${
          remoteCancellationError instanceof Error
            ? remoteCancellationError.message
            : 'unknown failure'
        }`,
        'DESKTOP_REMOTE_CANCEL_UNVERIFIED',
        503,
      );
    }

    session.state = 'stopped';
    const acknowledgement: DesktopTeardownAcknowledgement = {
      ...targetFromIdentity(session.identity),
      state: 'stopped',
      acknowledgedAt: new Date(this.now()).toISOString(),
      cooperative,
      forced,
      verified: true,
      remoteCancellationOperationId,
    };
    session.teardownAcknowledgement = acknowledgement;
    return acknowledgement;
  }

  getState(identity: DesktopControlIdentity) {
    return this.resolveSession(identity, false)?.state ?? null;
  }

  hasActiveOperation(identity: DesktopControlIdentity) {
    return Boolean(this.resolveSession(identity, false)?.activeOperation);
  }
}
