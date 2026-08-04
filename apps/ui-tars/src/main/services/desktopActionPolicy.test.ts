import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  isGovernedAgentSurface,
  resolveFencedMeshGateway,
} from './desktopActionPolicy';

describe('desktop action isolation policy', () => {
  it('rejects a main-process remote-computer agent loop', () => {
    expect(isGovernedAgentSurface('remote_computer')).toBe(false);
    expect(isGovernedAgentSurface('local_computer')).toBe(true);
  });

  it('keeps direct remote-computer effects out of the Electron bridge', () => {
    const source = readFileSync(join(__dirname, 'desktopRpcBridge.ts'), 'utf8');
    expect(source).not.toContain('new RemoteComputer(');
    expect(source).not.toContain('executeRemoteComputerAction(');
    const workerSource = readFileSync(
      join(__dirname, '../workers/desktopActionWorker.ts'),
      'utf8',
    );
    expect(workerSource).toContain('/_aillium/fence/verify');
    expect(workerSource).toContain('assertRemoteFenceAcknowledgement');
  });

  it('fails closed without an explicitly configured fenced Mesh gateway', () => {
    expect(resolveFencedMeshGateway(undefined)).toBeNull();
    expect(resolveFencedMeshGateway('   ')).toBeNull();
    expect(resolveFencedMeshGateway('https://mesh-gateway.example')).toBe(
      'https://mesh-gateway.example',
    );
  });
});
