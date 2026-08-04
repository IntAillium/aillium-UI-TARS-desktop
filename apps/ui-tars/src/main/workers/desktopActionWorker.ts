import { spawn } from 'node:child_process';
import { NutJSOperator } from '@ui-tars/operator-nut-js';
import {
  DefaultBrowserOperator,
  RemoteBrowserOperator,
  SearchEngine,
} from '@ui-tars/operator-browser';
import type { ExecuteParams } from '@ui-tars/sdk/core';
import type {
  DesktopActionProcessCommand,
  DesktopActionProcessResponse,
} from '../services/desktopActionProtocol';
import {
  assertRemoteFenceAcknowledgement,
  assertRemoteEffectProof,
  buildRemoteEffectDigest,
  buildRemoteFenceHeaders,
} from '../services/desktopRemoteFence';

function readString(value: unknown) {
  return typeof value === 'string' ? value : '';
}

function readNumber(value: unknown) {
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}

function pointBox(x: number, y: number) {
  return `[${x},${y},${x},${y}]`;
}

function params(
  parsedPrediction: Record<string, unknown>,
  width: number,
  height: number,
  scaleFactor: number,
): ExecuteParams {
  return {
    prediction: '',
    parsedPrediction:
      parsedPrediction as unknown as ExecuteParams['parsedPrediction'],
    screenWidth: width,
    screenHeight: height,
    scaleFactor,
    factors: [1, 1],
  };
}

async function runLocalComputer(command: DesktopActionProcessCommand) {
  const display = command.display;
  if (!display) throw new Error('Local computer display context is required');
  if (command.action === 'screen.get_size') return display;
  const operator = new NutJSOperator();
  if (command.action === 'screen.capture') return await operator.screenshot();
  const args = command.arguments;
  const x = readNumber(args.x) ?? readNumber(args.startX) ?? display.width / 2;
  const y = readNumber(args.y) ?? readNumber(args.startY) ?? display.height / 2;
  const endX = readNumber(args.endX) ?? x;
  const endY = readNumber(args.endY) ?? y;
  const prediction =
    command.action === 'input.type_text'
      ? {
          action_type: 'type',
          action_inputs: { content: readString(args.text) },
        }
      : command.action === 'input.hotkey'
        ? {
            action_type: 'hotkey',
            action_inputs: {
              key: readString(args.key) || readString(args.hotkey),
            },
          }
        : command.action === 'mouse.click'
          ? {
              action_type: 'click',
              action_inputs: { start_box: pointBox(x, y) },
            }
          : command.action === 'mouse.double_click'
            ? {
                action_type: 'double_click',
                action_inputs: { start_box: pointBox(x, y) },
              }
            : command.action === 'mouse.right_click'
              ? {
                  action_type: 'right_click',
                  action_inputs: { start_box: pointBox(x, y) },
                }
              : command.action === 'mouse.drag'
                ? {
                    action_type: 'drag',
                    action_inputs: {
                      start_box: pointBox(x, y),
                      end_box: pointBox(endX, endY),
                    },
                  }
                : command.action === 'mouse.scroll'
                  ? {
                      action_type: 'scroll',
                      action_inputs: {
                        start_box: pointBox(x, y),
                        direction: readString(args.direction) || 'down',
                      },
                    }
                  : null;
  if (!prediction)
    throw new Error(`Unsupported isolated native action: ${command.action}`);
  return await operator.execute(
    params(prediction, display.width, display.height, display.scaleFactor),
  );
}

async function runLocalBrowser(command: DesktopActionProcessCommand) {
  if (!DefaultBrowserOperator.hasBrowser()) {
    throw new Error('Local browser is not available');
  }
  const operator = await DefaultBrowserOperator.getInstance(
    false,
    false,
    false,
    true,
    command.searchEngine === 'baidu'
      ? SearchEngine.BAIDU
      : command.searchEngine === 'bing'
        ? SearchEngine.BING
        : SearchEngine.GOOGLE,
  );
  try {
    if (command.action === 'screen.capture') return await operator.screenshot();
    const args = command.arguments;
    const prediction =
      command.action === 'browser.navigate'
        ? {
            action_type: 'navigate',
            action_inputs: {
              content: readString(args.url) || readString(args.target),
            },
          }
        : command.action === 'browser.navigate_back'
          ? { action_type: 'navigate_back', action_inputs: {} }
          : command.action === 'input.type_text'
            ? {
                action_type: 'type',
                action_inputs: { content: readString(args.text) },
              }
            : command.action === 'input.hotkey'
              ? {
                  action_type: 'hotkey',
                  action_inputs: {
                    key: readString(args.key) || readString(args.hotkey),
                  },
                }
              : command.action === 'mouse.scroll'
                ? {
                    action_type: 'scroll',
                    action_inputs: {
                      direction: readString(args.direction) || 'down',
                    },
                  }
                : null;
    if (!prediction)
      throw new Error(`Unsupported isolated browser action: ${command.action}`);
    return await operator.execute(params(prediction, 1920, 1080, 1));
  } finally {
    await DefaultBrowserOperator.destroyInstance();
  }
}

async function runRemoteBrowser(command: DesktopActionProcessCommand) {
  if (!command.remoteBrowserCdpUrl) {
    throw new Error('Remote browser CDP descriptor is required');
  }
  const operator = await RemoteBrowserOperator.getInstance(
    command.remoteBrowserCdpUrl,
    false,
    false,
    false,
    true,
  );
  try {
    if (command.action === 'screen.capture') return await operator.screenshot();
    const args = command.arguments;
    const prediction =
      command.action === 'browser.navigate'
        ? {
            action_type: 'navigate',
            action_inputs: {
              content: readString(args.url) || readString(args.target),
            },
          }
        : command.action === 'browser.navigate_back'
          ? { action_type: 'navigate_back', action_inputs: {} }
          : command.action === 'input.type_text'
            ? {
                action_type: 'type',
                action_inputs: { content: readString(args.text) },
              }
            : command.action === 'input.hotkey'
              ? {
                  action_type: 'hotkey',
                  action_inputs: {
                    key: readString(args.key) || readString(args.hotkey),
                  },
                }
              : command.action === 'mouse.scroll'
                ? {
                    action_type: 'scroll',
                    action_inputs: {
                      direction: readString(args.direction) || 'down',
                    },
                  }
                : null;
    if (!prediction) {
      throw new Error(`Unsupported remote browser action: ${command.action}`);
    }
    return await operator.execute(params(prediction, 1920, 1080, 1));
  } finally {
    await RemoteBrowserOperator.destroyInstance();
  }
}

async function runRemoteComputer(command: DesktopActionProcessCommand) {
  const descriptor = command.remoteComputer;
  if (!descriptor) throw new Error('Remote computer descriptor is required');
  const args = command.arguments;
  const executionHeaders = buildRemoteFenceHeaders(
    command.operationId,
    command.identity,
  );
  const gatewayBaseUrl = descriptor.proxyUrl.replace(/\/$/, '');
  const signedHeaders = {
    'Content-Type': 'application/json',
    ...descriptor.authHeaders,
    ...executionHeaders,
    'X-Aillium-Desktop-Control': descriptor.desktopControlToken,
  };
  const executionEnvelope = {
    operationId: command.operationId,
    ...command.identity,
  };
  const request = async (path: string, body: Record<string, unknown>) => {
    const effectPath = `/${path}`;
    const effectPayload = { InstanceId: descriptor.instanceId, ...body };
    const digest = buildRemoteEffectDigest(effectPath, effectPayload);
    const effectHeaders = {
      ...signedHeaders,
      'X-Aillium-Effect-Digest': digest,
    };
    const expectedAcknowledgement = {
      ...executionHeaders,
      'X-Aillium-Effect-Digest': digest,
    };
    // Reserve this exact digest before the gateway may forward any effect.
    const fenceResponse = await fetch(
      `${gatewayBaseUrl}/_aillium/fence/verify`,
      {
        method: 'POST',
        headers: effectHeaders,
        body: JSON.stringify({
          _ailliumExecution: executionEnvelope,
          effect: { path: effectPath, payload: effectPayload },
        }),
      },
    );
    if (!fenceResponse.ok) {
      throw new Error(
        `Remote fence verification failed (${fenceResponse.status})`,
      );
    }
    assertRemoteFenceAcknowledgement(
      fenceResponse.headers,
      expectedAcknowledgement,
    );
    const fenceResult = (await fenceResponse.json()) as {
      accepted?: unknown;
      operationId?: unknown;
      digest?: unknown;
    };
    if (
      fenceResult.accepted !== true ||
      fenceResult.operationId !== command.operationId ||
      fenceResult.digest !== digest
    ) {
      throw new Error('Remote gateway did not accept the execution fence');
    }
    const response = await fetch(`${gatewayBaseUrl}${effectPath}`, {
      method: 'POST',
      headers: effectHeaders,
      body: JSON.stringify({
        ...effectPayload,
        _ailliumExecution: executionEnvelope,
      }),
    });
    if (!response.ok) {
      throw new Error(`Remote computer request failed (${response.status})`);
    }
    assertRemoteFenceAcknowledgement(response.headers, expectedAcknowledgement);
    const result = (await response.json()) as Record<string, unknown>;
    assertRemoteEffectProof(
      result,
      command.operationId,
      command.identity,
      digest,
    );
    return result;
  };
  if (command.action === 'screen.get_size') {
    const data = await request('GetScreenSize', {});
    const result = data.Result as
      | { Width?: unknown; Height?: unknown }
      | undefined;
    const width = readNumber(result?.Width);
    const height = readNumber(result?.Height);
    if (width === null || height === null) {
      throw new Error('Remote computer returned an invalid screen size');
    }
    return { width, height };
  }
  if (command.action === 'screen.capture') {
    const data = await request('TakeScreenshot', {});
    const result = data.Result as { Screenshot?: unknown } | undefined;
    const screenshot = readString(result?.Screenshot).replace(
      /^data:image\/jpeg;base64,/,
      '',
    );
    if (!screenshot) throw new Error('Remote screenshot data is missing');
    return { base64: screenshot, scaleFactor: 1 };
  }
  if (command.action === 'input.type_text') {
    await request('TypeText', { Text: readString(args.text) });
    return { ok: true };
  }
  if (command.action === 'input.hotkey') {
    await request('PressKey', {
      Key: readString(args.key) || readString(args.hotkey),
    });
    return { ok: true };
  }
  if (
    command.action === 'mouse.click' ||
    command.action === 'mouse.double_click' ||
    command.action === 'mouse.right_click'
  ) {
    const x = readNumber(args.x);
    const y = readNumber(args.y);
    if (x === null || y === null) throw new Error('x and y are required');
    await request('ClickMouse', {
      PositionX: x,
      PositionY: y,
      Button:
        command.action === 'mouse.double_click'
          ? 'DoubleLeft'
          : command.action === 'mouse.right_click'
            ? 'Right'
            : 'Left',
      Press: true,
      Release: true,
    });
    return { ok: true };
  }
  if (command.action === 'mouse.drag') {
    const sourceX = readNumber(args.startX);
    const sourceY = readNumber(args.startY);
    const targetX = readNumber(args.endX);
    const targetY = readNumber(args.endY);
    if (
      sourceX === null ||
      sourceY === null ||
      targetX === null ||
      targetY === null
    ) {
      throw new Error('startX, startY, endX, and endY are required');
    }
    await request('DragMouse', {
      SourceX: sourceX,
      SourceY: sourceY,
      TargetX: targetX,
      TargetY: targetY,
    });
    return { ok: true };
  }
  if (command.action === 'mouse.scroll') {
    const rawDirection = readString(args.direction).toLowerCase();
    const direction =
      rawDirection === 'up'
        ? 'Up'
        : rawDirection === 'left'
          ? 'Left'
          : rawDirection === 'right'
            ? 'Right'
            : 'Down';
    await request('Scroll', {
      PositionX: readNumber(args.x) ?? 0,
      PositionY: readNumber(args.y) ?? 0,
      Direction: direction,
      Amount: Math.min(readNumber(args.amount) ?? 1, 10),
    });
    return { ok: true };
  }
  throw new Error(`Unsupported remote computer action: ${command.action}`);
}

async function handle(command: DesktopActionProcessCommand) {
  if (command.surface === 'local_browser')
    return await runLocalBrowser(command);
  if (command.surface === 'remote_browser') {
    return await runRemoteBrowser(command);
  }
  if (command.surface === 'remote_computer') {
    return await runRemoteComputer(command);
  }
  return await runLocalComputer(command);
}

const parentPid = Number(process.env.AILLIUM_DESKTOP_ACTION_PARENT_PID);
let orphanTeardownStarted = false;
function terminateOrphanedProcessTree(exitCode: number) {
  if (orphanTeardownStarted) return;
  orphanTeardownStarted = true;
  if (process.platform !== 'win32') {
    try {
      process.kill(-process.pid, 'SIGKILL');
      return;
    } catch {
      process.exit(exitCode);
    }
  }
  try {
    const killer = spawn(
      'taskkill',
      ['/PID', String(process.pid), '/T', '/F'],
      { detached: true, stdio: 'ignore', windowsHide: true },
    );
    killer.unref();
    const fallback = setTimeout(() => process.exit(exitCode), 250);
    fallback.unref();
  } catch {
    process.exit(exitCode);
  }
}
const watchdog = setInterval(() => {
  if (!Number.isInteger(parentPid) || parentPid <= 0) {
    terminateOrphanedProcessTree(70);
    return;
  }
  try {
    process.kill(parentPid, 0);
  } catch {
    terminateOrphanedProcessTree(71);
  }
}, 100);
watchdog.unref();
process.once('disconnect', () => terminateOrphanedProcessTree(72));

process.once('message', (command: DesktopActionProcessCommand) => {
  void handle(command)
    .then((result) => {
      const response: DesktopActionProcessResponse = {
        operationId: command.operationId,
        identity: command.identity,
        ok: true,
        result,
      };
      process.send?.(response, () => process.exit(0));
    })
    .catch((error) => {
      const response: DesktopActionProcessResponse = {
        operationId: command.operationId,
        identity: command.identity,
        ok: false,
        error: error instanceof Error ? error.message : String(error),
      };
      process.send?.(response, () => process.exit(1));
    });
});
