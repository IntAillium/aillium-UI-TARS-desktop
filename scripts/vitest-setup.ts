import { vi } from 'vitest';

vi.mock('electron-log', () => ({
  default: {
    scope: () => ({
      info: console.info,
      error: console.error,
      warn: console.warn,
      debug: console.debug,
    }),
    initialize: vi.fn(),
    transports: {
      file: {
        level: 'info',
        getFile: () => ({ path: '/tmp/ui-tars-test.log' }),
      },
    },
  },
}));

// Mock electron
vi.mock('electron', () => ({
  app: {
    on: vi.fn(),
    getPath: vi.fn(() => '/tmp'),
    getVersion: vi.fn(() => '0.0.0-test'),
    isPackaged: false,
  },
  shell: {
    openPath: vi.fn(),
  },
}));
