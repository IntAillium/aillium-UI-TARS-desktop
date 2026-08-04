export type AgentDesktopSurface =
  | 'local_computer'
  | 'local_browser'
  | 'remote_browser'
  | 'remote_computer';

export function isGovernedAgentSurface(surface: AgentDesktopSurface) {
  // The high-level agent loop still owns its operator inside Electron main.
  // Remote computer one-shots are isolated, but the full recursive loop is not.
  return surface !== 'remote_computer';
}

export function resolveFencedMeshGateway(value: string | undefined) {
  const gateway = value?.trim() || '';
  return gateway || null;
}
