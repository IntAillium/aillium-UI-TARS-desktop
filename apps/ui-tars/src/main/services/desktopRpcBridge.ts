import {
  createServer as createHttpServer,
  type IncomingMessage,
  type ServerResponse,
} from 'node:http';
import type { AddressInfo } from 'node:net';
import { server as ipcServer } from '@main/ipcRoutes';
import { GUIAgentManager } from '@main/ipcRoutes/agent';
import { logger } from '@main/logger';
import { store } from '@main/store/create';
import { showWindow } from '@main/window/index';
import { getScreenSize } from '@main/utils/screen';
import { SettingStore } from '@main/store/setting';
import { Operator, SearchEngineForSettings } from '@main/store/types';
import { checkBrowserAvailability } from './browserCheck';
import { getAuthHeader } from '../remote/auth';
import { ProxyClient } from '../remote/proxyClient';
import {
  assertDesktopControlTarget,
  DesktopControlError,
  DesktopControlSessionRegistry,
  readDesktopControlTarget,
  verifyDesktopControlToken,
  type DesktopControlIdentity,
} from './desktopControlSessions';
import { IsolatedDesktopAction } from './desktopActionProcess';
import {
  isGovernedAgentSurface,
  resolveFencedMeshGateway,
} from './desktopActionPolicy';

type DesktopSurface =
  | 'remote_browser'
  | 'remote_computer'
  | 'local_browser'
  | 'local_computer';
type CapabilityCategory =
  | 'screen'
  | 'browser'
  | 'input'
  | 'computer'
  | 'agent'
  | 'remote_resource';

type CapabilityDescriptor = {
  action: string;
  surface: DesktopSurface;
  category: CapabilityCategory;
  description: string;
};

const DESKTOP_RPC_PORT = Number.parseInt(
  process.env.AILLIUM_UI_TARS_DESKTOP_BRIDGE_PORT ||
    process.env.AILLIUM_DESKTOP_BRIDGE_PORT ||
    '47891',
  10,
);
const DESKTOP_RPC_HOST =
  process.env.AILLIUM_UI_TARS_DESKTOP_BRIDGE_HOST?.trim() ||
  process.env.AILLIUM_DESKTOP_BRIDGE_HOST?.trim() ||
  '127.0.0.1';
// Dedicated secret for verifying short-lived, run-scoped desktop-control JWTs
// (never the login JWT_SECRET). An unscoped pairing token is not control
// authority; it must be exchanged for a scoped token by the durable runtime.
const DESKTOP_AUTHORITY_PUBLIC_KEY = (() => {
  const encoded =
    process.env.AILLIUM_DESKTOP_AUTHORITY_PUBLIC_KEY_BASE64?.trim() || '';
  if (!encoded) return '';
  try {
    return Buffer.from(encoded, 'base64').toString('utf8');
  } catch {
    return '';
  }
})();
const desktopSessions = new DesktopControlSessionRegistry();

const CAPABILITIES: CapabilityDescriptor[] = [
  {
    action: 'screen.get_size',
    surface: 'local_computer',
    category: 'screen',
    description: 'Read the primary display dimensions and scale factor.',
  },
  {
    action: 'screen.capture',
    surface: 'local_computer',
    category: 'screen',
    description: 'Capture the current desktop or controlled browser surface.',
  },
  {
    action: 'browser.check_availability',
    surface: 'local_browser',
    category: 'browser',
    description: 'Verify that the local browser operator can be started.',
  },
  {
    action: 'browser.navigate',
    surface: 'local_browser',
    category: 'browser',
    description: 'Navigate the active browser to a target URL.',
  },
  {
    action: 'browser.navigate_back',
    surface: 'local_browser',
    category: 'browser',
    description: 'Navigate back in the active browser tab.',
  },
  {
    action: 'input.type_text',
    surface: 'local_computer',
    category: 'input',
    description: 'Type text into the focused target.',
  },
  {
    action: 'input.hotkey',
    surface: 'local_computer',
    category: 'input',
    description: 'Send a keyboard shortcut to the active surface.',
  },
  {
    action: 'mouse.click',
    surface: 'local_computer',
    category: 'input',
    description: 'Click a specific coordinate on the active surface.',
  },
  {
    action: 'mouse.double_click',
    surface: 'local_computer',
    category: 'input',
    description: 'Double-click a specific coordinate on the active surface.',
  },
  {
    action: 'mouse.right_click',
    surface: 'local_computer',
    category: 'input',
    description: 'Right-click a specific coordinate on the active surface.',
  },
  {
    action: 'mouse.drag',
    surface: 'local_computer',
    category: 'input',
    description: 'Drag between two coordinates on the active surface.',
  },
  {
    action: 'mouse.scroll',
    surface: 'local_computer',
    category: 'input',
    description: 'Scroll the active surface in the requested direction.',
  },
  {
    action: 'computer.execute_instruction',
    surface: 'local_computer',
    category: 'computer',
    description:
      'Run a natural-language desktop instruction through the UI-TARS agent loop.',
  },
  {
    action: 'agent.run',
    surface: 'local_computer',
    category: 'agent',
    description: 'Start a UI-TARS agent run with the current instructions.',
  },
  {
    action: 'agent.pause',
    surface: 'local_computer',
    category: 'agent',
    description: 'Pause the active UI-TARS agent run.',
  },
  {
    action: 'agent.resume',
    surface: 'local_computer',
    category: 'agent',
    description: 'Resume the active UI-TARS agent run.',
  },
  {
    action: 'agent.stop',
    surface: 'local_computer',
    category: 'agent',
    description: 'Stop the active UI-TARS agent run.',
  },
  {
    action: 'remote.allocate_browser',
    surface: 'remote_browser',
    category: 'remote_resource',
    description: 'Allocate a remote browser resource.',
  },
  {
    action: 'remote.allocate_computer',
    surface: 'local_computer',
    category: 'remote_resource',
    description: 'Allocate a remote computer resource.',
  },
  {
    action: 'remote.release_resource',
    surface: 'remote_browser',
    category: 'remote_resource',
    description: 'Release a remote browser or computer resource.',
  },
  {
    action: 'remote.get_rdp_url',
    surface: 'local_computer',
    category: 'remote_resource',
    description:
      'Get the remote desktop endpoint for the allocated computer resource.',
  },
];

function sendJson(res: ServerResponse, status: number, body: unknown) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.end(JSON.stringify(body));
}

function readPresentedToken(req: IncomingMessage) {
  const authorization =
    typeof req.headers.authorization === 'string'
      ? req.headers.authorization
      : '';
  const bearerToken = authorization.startsWith('Bearer ')
    ? authorization.slice('Bearer '.length).trim()
    : '';
  const headerToken =
    typeof req.headers['x-aillium-desktop-token'] === 'string'
      ? req.headers['x-aillium-desktop-token'].trim()
      : '';
  return bearerToken || headerToken;
}

async function authorizeRequest(
  req: IncomingMessage,
  // secretlint-disable-next-line @secretlint/secretlint-rule-pattern -- return type names a runtime value, not an embedded secret
): Promise<{ identity: DesktopControlIdentity; token: string } | null> {
  // The bridge can control the desktop, so fail closed even on a local bind.
  if (!DESKTOP_AUTHORITY_PUBLIC_KEY) {
    return null;
  }

  const presented = readPresentedToken(req);
  if (!presented) {
    return null;
  }
  try {
    const identity = await verifyDesktopControlToken(
      presented,
      DESKTOP_AUTHORITY_PUBLIC_KEY,
    );
    // secretlint-disable-next-line @secretlint/secretlint-rule-pattern -- forwards a verified runtime bearer value
    return { identity, token: presented };
  } catch {
    return null;
  }
}

async function readJsonBody(
  req: IncomingMessage,
): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  const raw = Buffer.concat(chunks).toString('utf8').trim();
  return raw ? (JSON.parse(raw) as Record<string, unknown>) : {};
}

function readString(value: unknown) {
  return typeof value === 'string' && value.trim() ? value.trim() : null;
}

function resolveSurface(value: unknown): DesktopSurface {
  return value === 'remote_browser' ||
    value === 'remote_computer' ||
    value === 'local_browser' ||
    value === 'local_computer'
    ? value
    : 'local_computer';
}

function mapSurfaceToOperator(surface: DesktopSurface): Operator {
  switch (surface) {
    case 'remote_browser':
      return Operator.RemoteBrowser;
    case 'remote_computer':
      return Operator.RemoteComputer;
    case 'local_browser':
      return Operator.LocalBrowser;
    case 'local_computer':
    default:
      return Operator.LocalComputer;
  }
}

async function resolveRemoteComputerDescriptor(
  signal: AbortSignal,
  desktopControlToken: string,
) {
  const fencedGatewayUrl = resolveFencedMeshGateway(
    process.env.AILLIUM_MESH_FENCED_GATEWAY_URL,
  );
  if (!fencedGatewayUrl) {
    throw new DesktopControlError(
      'Remote computer control requires a fenced Mesh gateway',
      'DESKTOP_REMOTE_FENCING_REQUIRED',
      503,
    );
  }
  const sandbox = await ProxyClient.getSandboxInfo();
  if (!sandbox?.sandBoxId) {
    throw new Error('Remote computer resource is not available');
  }
  const authHeaders = await getAuthHeader();
  throwIfDesktopActionAborted(signal);
  return {
    instanceId: sandbox.sandBoxId,
    proxyUrl: fencedGatewayUrl,
    authHeaders,
    desktopControlToken,
  };
}

async function resolveRemoteBrowserCdpUrl(signal: AbortSignal) {
  let cdpUrl = await ProxyClient.getBrowserCDPUrl(signal);
  if (!cdpUrl) {
    await ProxyClient.allocResource('hdfBrowser', signal);
    cdpUrl = await ProxyClient.getBrowserCDPUrl(signal);
  }
  if (!cdpUrl) throw new Error('Remote browser resource is not available');
  return cdpUrl;
}

async function executeRemoteResourceAction(
  action: string,
  args: Record<string, unknown>,
  signal: AbortSignal,
) {
  if (action === 'remote.allocate_browser') {
    return await ProxyClient.allocResource('hdfBrowser', signal);
  }
  if (action === 'remote.allocate_computer') {
    return await ProxyClient.allocResource('computer', signal);
  }
  if (action === 'remote.release_resource') {
    const resourceType =
      readString(args.resourceType) === 'computer' ? 'computer' : 'hdfBrowser';
    return await ProxyClient.releaseResource(resourceType, signal);
  }
  if (action === 'remote.get_rdp_url') {
    return readString(args.resourceType) === 'hdfBrowser'
      ? await ProxyClient.getBrowserCDPUrl(signal)
      : await ProxyClient.getSandboxRDPUrl(signal);
  }
  throw new Error(`Unsupported remote resource action: ${action}`);
}

function desktopRuntimeControls() {
  return {
    pause: async () => {
      await ipcServer.pauseRun();
    },
    resume: async () => {
      await ipcServer.resumeRun();
    },
    cooperativeStop: async () => {
      await ipcServer.stopRun();
    },
    forceStop: () => {
      const manager = GUIAgentManager.getInstance();
      const abortController = store.getState().abortController;
      const agent = manager.getAgent();
      abortController?.abort();
      agent?.resume();
      agent?.stop();
      manager.clearAgent();
      store.setState({ abortController: null, thinking: false });
      // Let the normal IPC cleanup (window/marker state) finish, but do not let
      // a blocked cleanup handler extend the hard teardown deadline.
      void ipcServer.stopRun().catch((error) => {
        logger.error('[desktop-rpc-bridge] forced stop cleanup failed', error);
      });
    },
  };
}

function throwIfDesktopActionAborted(signal: AbortSignal) {
  if (signal.aborted) {
    throw signal.reason instanceof Error
      ? signal.reason
      : new DesktopControlError(
          'Desktop action was cancelled',
          'DESKTOP_SESSION_STOPPED',
          409,
        );
  }
}

async function performScopedAction(
  body: Record<string, unknown>,
  identity: DesktopControlIdentity,
  desktopControlToken: string,
) {
  const target = readDesktopControlTarget(body);
  assertDesktopControlTarget(identity, target);
  desktopSessions.ensure(identity);

  const action = readString(body.action);
  if (!action) {
    throw new Error('action is required');
  }

  if (action === 'agent.pause') {
    return desktopSessions.pause(identity);
  }
  if (action === 'agent.resume') {
    return desktopSessions.resume(identity);
  }
  if (action === 'agent.stop') {
    const args =
      body.arguments &&
      typeof body.arguments === 'object' &&
      !Array.isArray(body.arguments)
        ? (body.arguments as Record<string, unknown>)
        : {};
    return desktopSessions.stop(identity, {
      desktopControlToken,
      ...(typeof args.force === 'boolean' ? { force: args.force } : {}),
      ...(typeof args.deadlineMs === 'number' &&
      Number.isFinite(args.deadlineMs)
        ? { deadlineMs: args.deadlineMs }
        : {}),
    });
  }

  if (action === 'agent.run' || action === 'computer.execute_instruction') {
    const requestedSurface = resolveSurface(body.requestedSurface);
    if (!isGovernedAgentSurface(requestedSurface)) {
      throw new DesktopControlError(
        'The remote-computer agent loop is not isolated from Electron main',
        'DESKTOP_AGENT_ISOLATION_REQUIRED',
        409,
      );
    }
    return desktopSessions.runOwnedAction(
      identity,
      async (signal) => {
        const args =
          body.arguments &&
          typeof body.arguments === 'object' &&
          !Array.isArray(body.arguments)
            ? (body.arguments as Record<string, unknown>)
            : {};
        const instructions =
          readString(args.prompt) ?? readString(args.instructions);
        if (action === 'computer.execute_instruction' && !instructions) {
          throw new Error('prompt or instructions is required');
        }
        if (body.requestedSurface) {
          SettingStore.set('operator', mapSurfaceToOperator(requestedSurface));
        }
        if (instructions) {
          await ipcServer.setInstructions({ instructions });
          throwIfDesktopActionAborted(signal);
        }
        throwIfDesktopActionAborted(signal);
        await ipcServer.runAgent();
        throwIfDesktopActionAborted(signal);
        return action === 'computer.execute_instruction'
          ? { ok: true, instructions }
          : { ok: true };
      },
      desktopRuntimeControls(),
    );
  }

  const args =
    body.arguments &&
    typeof body.arguments === 'object' &&
    !Array.isArray(body.arguments)
      ? (body.arguments as Record<string, unknown>)
      : {};
  if (
    action === 'remote.allocate_browser' ||
    action === 'remote.allocate_computer' ||
    action === 'remote.release_resource' ||
    action === 'remote.get_rdp_url'
  ) {
    return desktopSessions.runOwnedAction(identity, async (signal) => {
      throwIfDesktopActionAborted(signal);
      const result = await executeRemoteResourceAction(action, args, signal);
      throwIfDesktopActionAborted(signal);
      return result;
    });
  }

  // Every direct browser, computer, keyboard, mouse, screenshot, and remote
  // resource action owns the physical desktop until its real promise settles.
  // Abort fences its result; stop cannot claim verified teardown merely because
  // local references were cleared while the underlying action is still alive.
  const requestedSurface = resolveSurface(body.requestedSurface);
  const isolatedSurface =
    action !== 'browser.check_availability' &&
    (requestedSurface === 'remote_browser' ||
      requestedSurface === 'remote_computer' ||
      requestedSurface === 'local_browser' ||
      requestedSurface === 'local_computer')
      ? requestedSurface
      : null;
  let isolatedAction: IsolatedDesktopAction | null = null;
  if (!isolatedSurface && action !== 'browser.check_availability') {
    throw new DesktopControlError(
      'This governed one-shot action has no killable runtime boundary',
      'DESKTOP_ACTION_ISOLATION_REQUIRED',
      409,
    );
  }
  return desktopSessions.runOwnedAction(
    identity,
    async (signal) => {
      throwIfDesktopActionAborted(signal);
      if (isolatedSurface) {
        const remoteBrowserCdpUrl =
          isolatedSurface === 'remote_browser'
            ? await resolveRemoteBrowserCdpUrl(signal)
            : undefined;
        const remoteComputer =
          isolatedSurface === 'remote_computer'
            ? await resolveRemoteComputerDescriptor(signal, desktopControlToken)
            : undefined;
        throwIfDesktopActionAborted(signal);
        const display =
          isolatedSurface === 'local_computer'
            ? (() => {
                const current = getScreenSize();
                return {
                  width: current.physicalSize.width,
                  height: current.physicalSize.height,
                  scaleFactor: current.scaleFactor,
                };
              })()
            : undefined;
        isolatedAction = new IsolatedDesktopAction(identity, {
          surface: isolatedSurface,
          action,
          arguments: args,
          ...(remoteBrowserCdpUrl ? { remoteBrowserCdpUrl } : {}),
          ...(remoteComputer ? { remoteComputer } : {}),
          ...(isolatedSurface === 'local_browser'
            ? {
                searchEngine:
                  SettingStore.getStore().searchEngineForBrowser ??
                  SearchEngineForSettings.GOOGLE,
              }
            : {}),
          ...(display ? { display } : {}),
        });
        return await isolatedAction.run(signal);
      }
      const result = await checkBrowserAvailability();
      throwIfDesktopActionAborted(signal);
      return result;
    },
    {
      ...(isolatedSurface === 'remote_computer'
        ? {
            cancelFence: async (
              nextIdentity: DesktopControlIdentity,
              nextDesktopControlToken: string,
              signal: AbortSignal,
            ) =>
              isolatedAction
                ? await isolatedAction.cancelRemoteFence(
                    nextIdentity,
                    nextDesktopControlToken,
                    signal,
                  )
                : null,
          }
        : {}),
      cooperativeStop: () => isolatedAction?.terminate(),
      forceStop: () => isolatedAction?.terminate(),
    },
  );
}

function buildCapabilitiesPayload() {
  const settings = SettingStore.getStore();
  return {
    available: true,
    rpcReady: true,
    provider: 'ui-tars-desktop',
    launchUrl: process.env.AILLIUM_OPERATOR_DESKTOP_URL?.trim() || null,
    activeOperator: settings.operator,
    capabilities: CAPABILITIES,
  };
}

export function startDesktopRpcBridge() {
  if (!DESKTOP_AUTHORITY_PUBLIC_KEY) {
    logger.warn(
      '[desktop-rpc-bridge] Desktop RPC bridge disabled: scoped desktop-control token verification is not configured. Set AILLIUM_DESKTOP_AUTHORITY_PUBLIC_KEY_BASE64.',
    );
  }

  const httpServer = createHttpServer(async (req, res) => {
    const requestPath = req.url?.split('?')[0] ?? '/';

    if ((req.method ?? 'GET').toUpperCase() !== 'POST') {
      sendJson(res, 405, { error: 'Method Not Allowed' });
      return;
    }

    const authorization = await authorizeRequest(req);
    if (!authorization) {
      sendJson(res, 401, { error: 'Unauthorized' });
      return;
    }

    try {
      const body = await readJsonBody(req);

      if (requestPath === '/capabilities') {
        sendJson(res, 200, buildCapabilitiesPayload());
        return;
      }

      if (requestPath === '/handoff') {
        const target = readDesktopControlTarget(body);
        assertDesktopControlTarget(authorization.identity, target);
        desktopSessions.assertAcceptsInput(authorization.identity);
        const requestedSurface = resolveSurface(body.requestedSurface);
        const prompt = readString(body.prompt);
        SettingStore.set('operator', mapSurfaceToOperator(requestedSurface));
        if (prompt) {
          await ipcServer.setInstructions({ instructions: prompt });
        }
        await showWindow();
        sendJson(res, 200, {
          handoffPrepared: true,
          requestedSurface,
          activeOperator: SettingStore.get('operator'),
          note:
            readString(body.reason) ||
            'Desktop handoff prepared in UI-TARS Desktop.',
        });
        return;
      }

      if (requestPath === '/invoke') {
        const result = await performScopedAction(
          body,
          authorization.identity,
          authorization.token,
        );
        sendJson(res, 200, {
          ok: true,
          action: readString(body.action),
          result,
        });
        return;
      }

      sendJson(res, 404, { error: 'Not Found' });
    } catch (error) {
      logger.error('[desktop-rpc-bridge]', error);
      sendJson(
        res,
        error instanceof DesktopControlError ? error.statusCode : 400,
        {
          error:
            error instanceof Error ? error.message : 'Desktop RPC bridge error',
          ...(error instanceof DesktopControlError ? { code: error.code } : {}),
        },
      );
    }
  });

  httpServer.listen(DESKTOP_RPC_PORT, DESKTOP_RPC_HOST, () => {
    const address = httpServer.address() as AddressInfo | null;
    logger.info(
      `[desktop-rpc-bridge] listening on http://${address?.address || DESKTOP_RPC_HOST}:${address?.port || DESKTOP_RPC_PORT}`,
    );
  });

  return {
    close: () =>
      new Promise<void>((resolve) => {
        httpServer.close(() => resolve());
      }),
  };
}
