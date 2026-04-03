import { createServer as createHttpServer, type IncomingMessage, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { server as ipcServer } from '@main/ipcRoutes';
import { logger } from '@main/logger';
import { showWindow } from '@main/window/index';
import { getScreenSize } from '@main/utils/screen';
import { SettingStore } from '@main/store/setting';
import { Operator, SearchEngineForSettings } from '@main/store/types';
import { checkBrowserAvailability } from './browserCheck';
import { NutJSElectronOperator } from '../agent/operator';
import { ProxyClient, RemoteComputer } from '../remote/proxyClient';
import { RemoteComputerOperator } from '../remote/operators';
import { DefaultBrowserOperator, RemoteBrowserOperator } from '@ui-tars/operator-browser';

type DesktopSurface = 'remote_browser' | 'local_browser' | 'local_computer';
type CapabilityCategory = 'screen' | 'browser' | 'input' | 'computer' | 'agent' | 'remote_resource';

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
const DESKTOP_RPC_TOKEN =
  process.env.AILLIUM_UI_TARS_DESKTOP_BRIDGE_TOKEN?.trim() ||
  process.env.AILLIUM_DESKTOP_BRIDGE_TOKEN?.trim() ||
  '';

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
    description: 'Run a natural-language desktop instruction through the UI-TARS agent loop.',
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
    description: 'Get the remote desktop endpoint for the allocated computer resource.',
  },
];

function sendJson(res: ServerResponse, status: number, body: unknown) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.end(JSON.stringify(body));
}

function isAuthorized(req: IncomingMessage) {
  if (!DESKTOP_RPC_TOKEN) {
    return true;
  }

  const authorization =
    typeof req.headers.authorization === 'string' ? req.headers.authorization : '';
  const bearerToken = authorization.startsWith('Bearer ')
    ? authorization.slice('Bearer '.length).trim()
    : '';
  const headerToken =
    typeof req.headers['x-aillium-desktop-token'] === 'string'
      ? req.headers['x-aillium-desktop-token'].trim()
      : '';
  const presented = bearerToken || headerToken;

  return presented.length > 0 && presented === DESKTOP_RPC_TOKEN;
}

async function readJsonBody(req: IncomingMessage): Promise<Record<string, unknown>> {
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

function readNumber(value: unknown) {
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}

function createPointBox(x: number, y: number) {
  const cx = Math.max(1, Math.round(x));
  const cy = Math.max(1, Math.round(y));
  return `[${cx}, ${cy}, ${cx}, ${cy}]`;
}

function createOperatorBox(x1: number, y1: number, x2: number, y2: number) {
  return `[${Math.round(x1)}, ${Math.round(y1)}, ${Math.round(x2)}, ${Math.round(y2)}]`;
}

function resolveSurface(value: unknown): DesktopSurface {
  return value === 'remote_browser' || value === 'local_browser' || value === 'local_computer'
    ? value
    : 'local_computer';
}

function mapSurfaceToOperator(surface: DesktopSurface): Operator {
  switch (surface) {
    case 'remote_browser':
      return Operator.RemoteBrowser;
    case 'local_browser':
      return Operator.LocalBrowser;
    case 'local_computer':
    default:
      return Operator.LocalComputer;
  }
}

async function getLocalBrowserOperator() {
  await checkBrowserAvailability();
  const settings = SettingStore.getStore();
  return DefaultBrowserOperator.getInstance(
    false,
    false,
    false,
    true,
    settings.searchEngineForBrowser ?? SearchEngineForSettings.GOOGLE,
  );
}

async function getRemoteBrowserOperator() {
  const existingUrl = await ProxyClient.getBrowserCDPUrl();
  const cdpUrl =
    existingUrl ||
    ((await ipcServer.allocRemoteResource({ resourceType: 'hdfBrowser' })) ? await ProxyClient.getBrowserCDPUrl() : null);
  if (!cdpUrl) {
    throw new Error('Remote browser resource is not available');
  }
  return RemoteBrowserOperator.getInstance(cdpUrl, false, false, false, true);
}

async function getRemoteComputerClient() {
  const sandbox = await ProxyClient.getSandboxInfo();
  if (!sandbox?.sandBoxId) {
    throw new Error('Remote computer resource is not available');
  }
  return new RemoteComputer(sandbox.sandBoxId);
}

async function executeBrowserAction(
  surface: DesktopSurface,
  action: string,
  args: Record<string, unknown>,
) {
  const operator =
    surface === 'remote_browser'
      ? await getRemoteBrowserOperator()
      : await getLocalBrowserOperator();

  if (action === 'screen.capture') {
    return await (operator as any).screenshot();
  }

  const parsedPrediction =
    action === 'browser.navigate'
      ? {
          action_type: 'navigate',
          action_inputs: { content: readString(args.url) ?? readString(args.target) ?? '' },
        }
      : action === 'browser.navigate_back'
        ? {
            action_type: 'navigate_back',
            action_inputs: {},
          }
        : action === 'input.type_text'
          ? {
              action_type: 'type',
              action_inputs: { content: readString(args.text) ?? '' },
            }
          : action === 'input.hotkey'
            ? {
                action_type: 'hotkey',
                action_inputs: { key: readString(args.key) ?? readString(args.hotkey) ?? '' },
              }
            : action === 'mouse.scroll'
              ? {
                  action_type: 'scroll',
                  action_inputs: { direction: readString(args.direction) ?? 'down' },
                }
              : null;

  if (!parsedPrediction) {
    throw new Error(`Unsupported browser action: ${action}`);
  }

  return await (operator as any).execute({
    parsedPrediction,
    screenWidth: 1920,
    screenHeight: 1080,
    scaleFactor: 1,
  } as any);
}

async function executeLocalComputerAction(action: string, args: Record<string, unknown>) {
  const operator = new NutJSElectronOperator();
  const display = getScreenSize();

  if (action === 'screen.get_size') {
    return {
      width: display.physicalSize.width,
      height: display.physicalSize.height,
      scaleFactor: display.scaleFactor,
    };
  }

  if (action === 'screen.capture') {
    return await operator.screenshot();
  }

  const x = readNumber(args.x) ?? readNumber(args.startX) ?? Math.round(display.physicalSize.width / 2);
  const y = readNumber(args.y) ?? readNumber(args.startY) ?? Math.round(display.physicalSize.height / 2);
  const endX = readNumber(args.endX);
  const endY = readNumber(args.endY);

  const parsedPrediction =
    action === 'input.type_text'
      ? {
          action_type: 'type',
          action_inputs: { content: readString(args.text) ?? '' },
        }
      : action === 'input.hotkey'
        ? {
            action_type: 'hotkey',
            action_inputs: { key: readString(args.key) ?? readString(args.hotkey) ?? '' },
          }
        : action === 'mouse.click'
          ? {
              action_type: 'click',
              action_inputs: { start_box: createPointBox(x, y) },
            }
          : action === 'mouse.double_click'
            ? {
                action_type: 'double_click',
                action_inputs: { start_box: createPointBox(x, y) },
              }
            : action === 'mouse.right_click'
              ? {
                  action_type: 'right_click',
                  action_inputs: { start_box: createPointBox(x, y) },
                }
              : action === 'mouse.drag'
                ? {
                    action_type: 'drag',
                    action_inputs: {
                      start_box: createPointBox(x, y),
                      end_box: createOperatorBox(
                        endX ?? x,
                        endY ?? y,
                        endX ?? x,
                        endY ?? y,
                      ),
                    },
                  }
                : action === 'mouse.scroll'
                  ? {
                      action_type: 'scroll',
                      action_inputs: {
                        start_box: createPointBox(x, y),
                        direction: readString(args.direction) ?? 'down',
                      },
                    }
                  : null;

  if (!parsedPrediction) {
    throw new Error(`Unsupported local computer action: ${action}`);
  }

  return await operator.execute({
    parsedPrediction,
    screenWidth: display.physicalSize.width,
    screenHeight: display.physicalSize.height,
    scaleFactor: display.scaleFactor,
  } as any);
}

async function executeRemoteComputerAction(action: string, args: Record<string, unknown>) {
  const remoteComputer = await getRemoteComputerClient();

  if (action === 'screen.get_size') {
    return await remoteComputer.getScreenSize();
  }

  if (action === 'screen.capture') {
    return {
      base64: await remoteComputer.takeScreenshot(),
      scaleFactor: 1,
    };
  }

  if (action === 'input.type_text') {
    await remoteComputer.typeText(readString(args.text) ?? '');
    return { ok: true };
  }

  if (action === 'mouse.click' || action === 'mouse.double_click' || action === 'mouse.right_click') {
    const x = readNumber(args.x);
    const y = readNumber(args.y);
    if (x === null || y === null) {
      throw new Error('x and y are required');
    }
    await remoteComputer.clickMouse(
      x,
      y,
      action === 'mouse.double_click' ? 'DoubleLeft' : action === 'mouse.right_click' ? 'Right' : 'Left',
      true,
      true,
    );
    return { ok: true };
  }

  if (action === 'mouse.drag') {
    const startX = readNumber(args.startX);
    const startY = readNumber(args.startY);
    const endX = readNumber(args.endX);
    const endY = readNumber(args.endY);
    if (startX === null || startY === null || endX === null || endY === null) {
      throw new Error('startX, startY, endX, and endY are required');
    }
    await remoteComputer.dragMouse(startX, startY, endX, endY);
    return { ok: true };
  }

  if (action === 'mouse.scroll') {
    const x = readNumber(args.x) ?? 0;
    const y = readNumber(args.y) ?? 0;
    const rawDirection = readString(args.direction)?.toLowerCase() ?? 'down';
    const direction =
      rawDirection === 'up'
        ? 'Up'
        : rawDirection === 'left'
          ? 'Left'
          : rawDirection === 'right'
            ? 'Right'
            : 'Down';
    await remoteComputer.scroll(x, y, direction, readNumber(args.amount) ?? 1);
    return { ok: true };
  }

  if (action === 'input.hotkey') {
    const operator = await RemoteComputerOperator.create();
    return await operator.execute({
      parsedPrediction: {
        action_type: 'hotkey',
        action_inputs: { key: readString(args.key) ?? readString(args.hotkey) ?? '' },
      },
      screenWidth: 1,
      screenHeight: 1,
      scaleFactor: 1,
    } as any);
  }

  throw new Error(`Unsupported remote computer action: ${action}`);
}

async function performAction(body: Record<string, unknown>) {
  const action = readString(body.action);
  if (!action) {
    throw new Error('action is required');
  }

  const requestedSurface = resolveSurface(body.requestedSurface);
  const args =
    body.arguments && typeof body.arguments === 'object' && !Array.isArray(body.arguments)
      ? (body.arguments as Record<string, unknown>)
      : {};

  switch (action) {
    case 'browser.check_availability':
      return await checkBrowserAvailability();
    case 'browser.navigate':
    case 'browser.navigate_back':
    case 'input.type_text':
    case 'input.hotkey':
    case 'mouse.scroll':
    case 'screen.capture':
      if (requestedSurface === 'remote_browser' || requestedSurface === 'local_browser') {
        return await executeBrowserAction(requestedSurface, action, args);
      }
      if (requestedSurface === 'local_computer') {
        return await executeLocalComputerAction(action, args);
      }
      return await executeRemoteComputerAction(action, args);
    case 'screen.get_size':
    case 'mouse.click':
    case 'mouse.double_click':
    case 'mouse.right_click':
    case 'mouse.drag':
      return requestedSurface === 'local_computer'
        ? await executeLocalComputerAction(action, args)
        : await executeRemoteComputerAction(action, args);
    case 'computer.execute_instruction': {
      const instructions = readString(args.prompt) ?? readString(args.instructions);
      if (!instructions) {
        throw new Error('prompt or instructions is required');
      }
      SettingStore.set('operator', mapSurfaceToOperator(requestedSurface));
      await ipcServer.setInstructions({ instructions });
      await ipcServer.runAgent();
      return { ok: true, instructions };
    }
    case 'agent.run': {
      const instructions = readString(args.prompt) ?? readString(args.instructions);
      if (instructions) {
        await ipcServer.setInstructions({ instructions });
      }
      if (body.requestedSurface) {
        SettingStore.set('operator', mapSurfaceToOperator(requestedSurface));
      }
      await ipcServer.runAgent();
      return { ok: true };
    }
    case 'agent.pause':
      await ipcServer.pauseRun();
      return { ok: true };
    case 'agent.resume':
      await ipcServer.resumeRun();
      return { ok: true };
    case 'agent.stop':
      await ipcServer.stopRun();
      return { ok: true };
    case 'remote.allocate_browser':
      return await ipcServer.allocRemoteResource({ resourceType: 'hdfBrowser' });
    case 'remote.allocate_computer':
      return await ipcServer.allocRemoteResource({ resourceType: 'computer' });
    case 'remote.release_resource': {
      const resourceType =
        readString(args.resourceType) === 'computer' ? 'computer' : 'hdfBrowser';
      return await ipcServer.releaseRemoteResource({ resourceType });
    }
    case 'remote.get_rdp_url': {
      const resourceType =
        readString(args.resourceType) === 'hdfBrowser' ? 'hdfBrowser' : 'computer';
      return await ipcServer.getRemoteResourceRDPUrl({ resourceType });
    }
    default:
      throw new Error(`Unsupported desktop RPC action: ${action}`);
  }
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
  const httpServer = createHttpServer(async (req, res) => {
    const requestPath = req.url?.split('?')[0] ?? '/';

    if ((req.method ?? 'GET').toUpperCase() !== 'POST') {
      sendJson(res, 405, { error: 'Method Not Allowed' });
      return;
    }

    if (!isAuthorized(req)) {
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
        const result = await performAction(body);
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
      sendJson(res, 400, {
        error: error instanceof Error ? error.message : 'Desktop RPC bridge error',
      });
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
