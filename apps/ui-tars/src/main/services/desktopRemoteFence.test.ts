import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  assertRemoteCancellationProof,
  assertRemoteEffectProof,
  assertRemoteFenceAcknowledgement,
  buildRemoteEffectDigest,
  buildRemoteFenceHeaders,
  requestRemoteFenceCancellation,
} from './desktopRemoteFence';
import type { DesktopControlTarget } from './desktopControlSessions';

const identity: DesktopControlTarget = {
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
  cancellationGeneration: 3,
};

describe('remote computer fence envelope', () => {
  afterEach(() => vi.unstubAllGlobals());
  it('uses the same canonical effect digest as the fenced Mesh gateway', () => {
    expect(
      buildRemoteEffectDigest('/ClickMouse', {
        InstanceId: 'device-1',
        x: 12,
        y: 34,
      }),
    ).toBe('d5c440bfa3f53475c58ff60ab1405f74150c4d094123a774a2d5e2bd1d2fa4ee');
  });

  it('carries exact execution and idempotency identity', () => {
    expect(buildRemoteFenceHeaders('operation-1', identity)).toEqual({
      'X-Aillium-Operation-Id': 'operation-1',
      'Idempotency-Key': 'operation-1',
      'X-Aillium-Tenant-Id': 'tenant-1',
      'X-Aillium-Work-Order-Id': 'work-1',
      'X-Aillium-Authority-Type': 'agent',
      'X-Aillium-Authority-Id': 'agent-1',
      'X-Aillium-Run-Id': 'run-1',
      'X-Aillium-Run-Step-Id': 'step-1',
      'X-Aillium-Desktop-Session-Id': 'desktop-1',
      'X-Aillium-Attempt': '2',
      'X-Aillium-Executor-Id': 'executor-1',
      'X-Aillium-Fence-Token': '8',
      'X-Aillium-Cancellation-Generation': '3',
    });
  });

  it('fails closed when the gateway does not acknowledge the exact fence', () => {
    const expected = buildRemoteFenceHeaders('operation-1', identity);
    const acknowledged = new Headers(expected);
    expect(() =>
      assertRemoteFenceAcknowledgement(acknowledged, expected),
    ).not.toThrow();

    acknowledged.set('X-Aillium-Fence-Token', '7');
    expect(() =>
      assertRemoteFenceAcknowledgement(acknowledged, expected),
    ).toThrow('X-Aillium-Fence-Token');

    acknowledged.set('X-Aillium-Fence-Token', '8');
    acknowledged.set('Idempotency-Key', 'operation-2');
    expect(() =>
      assertRemoteFenceAcknowledgement(acknowledged, expected),
    ).toThrow('Idempotency-Key');
  });

  it('requires a completed proof correlated to the exact effect identity', () => {
    const body = {
      _ailliumProof: {
        operationId: 'operation-1',
        digest: 'digest-1',
        status: 'completed',
        identity,
      },
    };
    expect(() =>
      assertRemoteEffectProof(body, 'operation-1', identity, 'digest-1'),
    ).not.toThrow();
    expect(() =>
      assertRemoteEffectProof(body, 'operation-1', identity, 'digest-2'),
    ).toThrow('mismatched');
    expect(() =>
      assertRemoteEffectProof(
        {
          _ailliumProof: {
            ...body._ailliumProof,
            identity: { ...identity, cancellationGeneration: 2 },
          },
        },
        'operation-1',
        identity,
        'digest-1',
      ),
    ).toThrow('cancellationGeneration');
  });

  it('requires exact signed cancellation acknowledgement and correlated proof', async () => {
    const cancellationIdentity = { ...identity, cancellationGeneration: 4 };
    const expectedHeaders = buildRemoteFenceHeaders(
      'cancel-operation-1',
      cancellationIdentity,
    );
    const fetchMock = vi.fn(
      async () =>
        new Response(
          JSON.stringify({
            accepted: true,
            operationId: 'cancel-operation-1',
            cancelledOperationId: 'effect-operation-1',
            _ailliumProof: {
              operationId: 'cancel-operation-1',
              status: 'cancelled',
              identity: cancellationIdentity,
            },
          }),
          { status: 200, headers: expectedHeaders },
        ),
    );
    vi.stubGlobal('fetch', fetchMock);

    await expect(
      requestRemoteFenceCancellation(
        {
          instanceId: 'device-1',
          proxyUrl: 'https://gateway.example/',
          authHeaders: { Authorization: 'Bearer mesh' },
          desktopControlToken: 'old-token',
        },
        'cancel-operation-1',
        'signed-new-generation-token',
        cancellationIdentity,
      ),
    ).resolves.toMatchObject({
      operationId: 'cancel-operation-1',
      cancelledOperationId: 'effect-operation-1',
    });
    expect(fetchMock).toHaveBeenCalledWith(
      'https://gateway.example/_aillium/fence/cancel',
      expect.objectContaining({
        method: 'POST',
        headers: expect.objectContaining({
          'X-Aillium-Desktop-Control': 'signed-new-generation-token',
          'X-Aillium-Cancellation-Generation': '4',
          'Idempotency-Key': 'cancel-operation-1',
        }),
      }),
    );

    expect(() =>
      assertRemoteCancellationProof(
        {
          accepted: true,
          operationId: 'cancel-operation-1',
          _ailliumProof: {
            operationId: 'cancel-operation-1',
            status: 'cancelled',
            identity: { ...cancellationIdentity, cancellationGeneration: 3 },
          },
        },
        'cancel-operation-1',
        cancellationIdentity,
      ),
    ).toThrow('cancellationGeneration');
  });
});
