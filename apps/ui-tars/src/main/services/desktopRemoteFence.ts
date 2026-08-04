import { createHash } from 'node:crypto';
import type { RemoteComputerDescriptor } from './desktopActionProtocol';
import type { DesktopControlTarget } from './desktopControlSessions';

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value as Record<string, unknown>)
      .sort()
      .map(
        (key) =>
          `${JSON.stringify(key)}:${canonicalJson((value as Record<string, unknown>)[key])}`,
      )
      .join(',')}}`;
  }
  return JSON.stringify(value);
}

export function buildRemoteEffectDigest(
  path: string,
  payload: Record<string, unknown>,
) {
  return createHash('sha256')
    .update(canonicalJson({ path, payload }))
    .digest('hex');
}

export function buildRemoteFenceHeaders(
  operationId: string,
  identity: DesktopControlTarget,
): Record<string, string> {
  return {
    'X-Aillium-Operation-Id': operationId,
    'Idempotency-Key': operationId,
    'X-Aillium-Tenant-Id': identity.tenantId,
    'X-Aillium-Work-Order-Id': identity.workOrderId,
    'X-Aillium-Authority-Type': identity.authorityType,
    'X-Aillium-Authority-Id': identity.authorityId,
    'X-Aillium-Run-Id': identity.runId,
    'X-Aillium-Run-Step-Id': identity.runStepId,
    'X-Aillium-Desktop-Session-Id': identity.desktopSessionId,
    'X-Aillium-Attempt': String(identity.attempt),
    'X-Aillium-Executor-Id': identity.executorId,
    'X-Aillium-Fence-Token': identity.fenceToken,
    'X-Aillium-Cancellation-Generation': String(
      identity.cancellationGeneration,
    ),
  };
}

export function assertRemoteFenceAcknowledgement(
  headers: Pick<Headers, 'get'>,
  expectedHeaders: Record<string, string>,
) {
  for (const [name, expected] of Object.entries(expectedHeaders)) {
    if (headers.get(name) !== expected) {
      throw new Error(`Remote computer fence acknowledgement missing: ${name}`);
    }
  }
}

export function assertRemoteEffectProof(
  body: Record<string, unknown>,
  operationId: string,
  identity: DesktopControlTarget,
  digest: string,
) {
  const proof = body._ailliumProof;
  if (!proof || typeof proof !== 'object' || Array.isArray(proof)) {
    throw new Error('Remote computer effect proof is missing');
  }
  const record = proof as Record<string, unknown>;
  if (
    record.operationId !== operationId ||
    record.digest !== digest ||
    record.status !== 'completed'
  ) {
    throw new Error('Remote computer effect proof is mismatched');
  }
  const proofIdentity = record.identity;
  if (
    !proofIdentity ||
    typeof proofIdentity !== 'object' ||
    Array.isArray(proofIdentity)
  ) {
    throw new Error('Remote computer effect proof identity is missing');
  }
  for (const [field, expected] of Object.entries(identity)) {
    if (
      String((proofIdentity as Record<string, unknown>)[field]) !==
      String(expected)
    ) {
      throw new Error(
        `Remote computer effect proof identity mismatch: ${field}`,
      );
    }
  }
}

export function assertRemoteCancellationProof(
  body: Record<string, unknown>,
  operationId: string,
  identity: DesktopControlTarget,
) {
  const proof = body._ailliumProof;
  if (
    body.accepted !== true ||
    body.operationId !== operationId ||
    !proof ||
    typeof proof !== 'object' ||
    Array.isArray(proof)
  ) {
    throw new Error('Remote computer cancellation proof is missing');
  }
  const record = proof as Record<string, unknown>;
  if (record.operationId !== operationId || record.status !== 'cancelled') {
    throw new Error('Remote computer cancellation proof is mismatched');
  }
  const proofIdentity = record.identity;
  if (
    !proofIdentity ||
    typeof proofIdentity !== 'object' ||
    Array.isArray(proofIdentity)
  ) {
    throw new Error('Remote computer cancellation proof identity is missing');
  }
  for (const [field, expected] of Object.entries(identity)) {
    if (
      String((proofIdentity as Record<string, unknown>)[field]) !==
      String(expected)
    ) {
      throw new Error(
        `Remote computer cancellation proof identity mismatch: ${field}`,
      );
    }
  }
}

export async function requestRemoteFenceCancellation(
  descriptor: RemoteComputerDescriptor,
  operationId: string,
  desktopControlToken: string,
  identity: DesktopControlTarget,
  signal?: AbortSignal,
) {
  const executionHeaders = buildRemoteFenceHeaders(operationId, identity);
  const response = await fetch(
    `${descriptor.proxyUrl.replace(/\/$/, '')}/_aillium/fence/cancel`,
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...descriptor.authHeaders,
        ...executionHeaders,
        'X-Aillium-Desktop-Control': desktopControlToken,
      },
      body: JSON.stringify({
        _ailliumExecution: { operationId, ...identity },
      }),
      signal,
    },
  );
  if (!response.ok) {
    throw new Error(
      `Remote computer cancellation was not acknowledged (${response.status})`,
    );
  }
  assertRemoteFenceAcknowledgement(response.headers, executionHeaders);
  const result = (await response.json()) as Record<string, unknown>;
  assertRemoteCancellationProof(result, operationId, identity);
  return result;
}
