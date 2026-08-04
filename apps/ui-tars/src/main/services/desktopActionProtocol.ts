import type { DesktopControlTarget } from './desktopControlSessions';

export type IsolatedDesktopSurface =
  | 'local_browser'
  | 'local_computer'
  | 'remote_browser'
  | 'remote_computer';

export type RemoteComputerDescriptor = {
  instanceId: string;
  proxyUrl: string;
  authHeaders: Record<string, string>;
  desktopControlToken: string;
};

export type DesktopActionProcessCommand = {
  operationId: string;
  identity: DesktopControlTarget;
  surface: IsolatedDesktopSurface;
  action: string;
  arguments: Record<string, unknown>;
  searchEngine?: 'google' | 'baidu' | 'bing';
  remoteBrowserCdpUrl?: string;
  remoteComputer?: RemoteComputerDescriptor;
  display?: {
    width: number;
    height: number;
    scaleFactor: number;
  };
};

export type DesktopActionProcessResponse = {
  operationId: string;
  identity: DesktopControlTarget;
  ok: boolean;
  result?: unknown;
  error?: string;
};
