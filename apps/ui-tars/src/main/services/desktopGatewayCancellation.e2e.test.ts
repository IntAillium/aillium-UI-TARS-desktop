import { generateKeyPairSync } from 'node:crypto';
import { createRequire } from 'node:module';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import type { Server } from 'node:http';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { importPKCS8, SignJWT } from 'jose';
import { expect, it } from 'vitest';

import { requestRemoteFenceCancellation } from './desktopRemoteFence';
import type { DesktopControlTarget } from './desktopControlSessions';

type FenceStore = {
  initialize(): Promise<unknown>;
  close(): Promise<void>;
};

type Gateway = {
  createServer(): Server;
  close(): Promise<void>;
};

type MeshModules = {
  FileFenceStore: new (filePath: string) => FenceStore;
  createFencedGateway(options: {
    corePublicKeyPem: string;
    store: FenceStore;
    executeMeshAction: (
      route: string,
      payload: Record<string, unknown>,
      headers: Record<string, string>,
      signal: AbortSignal,
    ) => Promise<Record<string, unknown>>;
  }): Gateway;
  executeFencedEffect(options: {
    gatewayUrl: string;
    // secretlint-disable-next-line @secretlint/secretlint-rule-pattern -- signed test fixture, not a credential
    token: string;
    identity: DesktopControlTarget;
    operationId: string;
    path: string;
    payload: Record<string, unknown>;
  }): Promise<Record<string, unknown>>;
};

const runGatewayE2E = process.env.AILLIUM_ENABLE_GATEWAY_E2E_TEST === '1';

it.runIf(runGatewayE2E)(
  'Desktop signed cancellation aborts upstream, durably advances generation, and prevents the stale effect',
  async () => {
    const require = createRequire(import.meta.url);
    const meshDirectory = resolve(
      process.cwd(),
      '../aillium-remote-meshcentral/aillium',
    );
    const { FileFenceStore } = require(
      join(meshDirectory, 'fencedGateway.store.js'),
    ) as Pick<MeshModules, 'FileFenceStore'>;
    const { createFencedGateway } = require(
      join(meshDirectory, 'fencedGateway.service.js'),
    ) as Pick<MeshModules, 'createFencedGateway'>;
    const { executeFencedEffect } = require(
      join(meshDirectory, 'fencedGateway.client.js'),
    ) as Pick<MeshModules, 'executeFencedEffect'>;

    const keys = generateKeyPairSync('ed25519');
    const privateKeyPem = keys.privateKey.export({
      type: 'pkcs8',
      format: 'pem',
    }) as string;
    const publicKeyPem = keys.publicKey.export({
      type: 'spki',
      format: 'pem',
    }) as string;
    const signingKey = await importPKCS8(privateKeyPem, 'EdDSA');
    const sign = (target: DesktopControlTarget) =>
      new SignJWT({
        purpose: 'desktop-control',
        tenant_id: target.tenantId,
        work_order_id: target.workOrderId,
        authority_type: target.authorityType,
        authority_id: target.authorityId,
        run_id: target.runId,
        run_step_id: target.runStepId,
        desktop_session_id: target.desktopSessionId,
        attempt: target.attempt,
        executor_id: target.executorId,
        fence_token: target.fenceToken,
        cancellation_generation: target.cancellationGeneration,
      })
        .setProtectedHeader({ alg: 'EdDSA' })
        .setIssuer('aillium-core')
        .setAudience('aillium-desktop')
        .setExpirationTime(Math.floor(Date.now() / 1000) + 300)
        .sign(signingKey);

    const original: DesktopControlTarget = {
      tenantId: 'tenant-e2e',
      workOrderId: 'work-e2e',
      authorityType: 'agent',
      authorityId: 'finance-agent',
      runId: 'run-e2e',
      runStepId: 'step-e2e',
      desktopSessionId: 'desktop-e2e',
      attempt: 1,
      executorId: 'desktop-executor-e2e',
      fenceToken: '10',
      cancellationGeneration: 0,
    };
    const cancelled: DesktopControlTarget = {
      ...original,
      cancellationGeneration: 1,
    };
    const directory = await mkdtemp(join(tmpdir(), 'aillium-desktop-gateway-'));
    const storePath = join(directory, 'fences.json');
    const store = new FileFenceStore(storePath);
    await store.initialize();
    let startedResolve!: () => void;
    const started = new Promise<void>((resolveStarted) => {
      startedResolve = resolveStarted;
    });
    let applied = 0;
    let upstreamAborted = false;
    const gateway = createFencedGateway({
      corePublicKeyPem: publicKeyPem,
      store,
      executeMeshAction: async (_route, _payload, _headers, signal) => {
        startedResolve();
        await new Promise<void>((_resolve, reject) => {
          signal.addEventListener(
            'abort',
            () => {
              upstreamAborted = true;
              reject(signal.reason);
            },
            { once: true },
          );
        });
        applied += 1;
        return { ok: true };
      },
    });
    const server = gateway.createServer();
    try {
      await new Promise<void>((resolveListen, reject) => {
        server.once('error', reject);
        server.listen(0, '127.0.0.1', resolveListen);
      });
      const address = server.address();
      if (!address || typeof address === 'string')
        throw new Error('Gateway did not bind TCP');
      const gatewayUrl = `http://127.0.0.1:${address.port}`;
      const effectOperationId = 'effect-desktop-e2e';
      const oldEffect = executeFencedEffect({
        gatewayUrl,
        // secretlint-disable-next-line @secretlint/secretlint-rule-pattern -- signed test fixture, not a credential
        token: await sign(original),
        identity: original,
        operationId: effectOperationId,
        path: '/ClickMouse',
        payload: { InstanceId: 'device-e2e', x: 10, y: 20 },
      }).then(
        (result) => ({ ok: true as const, result }),
        (error: unknown) => ({ ok: false as const, error }),
      );
      await started;

      const cancellation = await requestRemoteFenceCancellation(
        {
          instanceId: 'device-e2e',
          proxyUrl: gatewayUrl,
          authHeaders: {},
          desktopControlToken: await sign(original),
        },
        'cancel-desktop-e2e',
        await sign(cancelled),
        cancelled,
      );
      expect(cancellation).toMatchObject({
        accepted: true,
        operationId: 'cancel-desktop-e2e',
        cancelledOperationId: effectOperationId,
      });
      await expect(oldEffect).resolves.toMatchObject({
        ok: false,
        error: { statusCode: 409 },
      });
      expect(upstreamAborted).toBe(true);
      expect(applied).toBe(0);

      const durable = JSON.parse(await readFile(storePath, 'utf8')) as {
        lineages: Record<string, { cancellationGeneration: number }>;
        operations: Record<string, { kind?: string; status: string }>;
      };
      expect(Object.values(durable.lineages)[0]?.cancellationGeneration).toBe(
        1,
      );
      expect(
        durable.operations['tenant-e2e\u001fcancel-desktop-e2e'],
      ).toMatchObject({ kind: 'cancellation', status: 'completed' });
      expect(
        durable.operations['tenant-e2e\u001feffect-desktop-e2e'],
      ).toMatchObject({ status: 'unknown' });
    } finally {
      if (server.listening) {
        await new Promise<void>((resolveClose, reject) =>
          server.close((error) => (error ? reject(error) : resolveClose())),
        );
      }
      await gateway.close();
      await rm(directory, { recursive: true, force: true });
    }
  },
);
