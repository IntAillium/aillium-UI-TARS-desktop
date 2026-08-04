import { describe, expect, it, vi } from 'vitest';
import { fetchWithAuth } from './proxyClient';

function response(data: unknown): Response {
  return {
    ok: true,
    headers: new Headers(),
    json: async () => data,
  } as Response;
}

const auth = async () => ({
  'X-Device-Id': 'test-device',
  'X-Timestamp': '1',
  Authorization: 'Bearer ephemeral-test-token',
});

describe('governed remote transport cancellation', () => {
  it('aborts a blocked remote operation inside the 500ms force deadline', async () => {
    const controller = new AbortController();
    const fetchImpl = vi.fn(
      (_url: string | URL | Request, init?: RequestInit) =>
        new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener(
            'abort',
            () => reject(init.signal?.reason),
            { once: true },
          );
        }),
    );
    const running = fetchWithAuth(
      'https://remote.invalid/action',
      { signal: controller.signal },
      1,
      { fetch: fetchImpl as typeof fetch, getAuthHeader: auth },
    );
    await vi.waitFor(() => expect(fetchImpl).toHaveBeenCalledTimes(1));

    const startedAt = Date.now();
    controller.abort(new Error('forced remote stop'));

    await expect(running).rejects.toThrow('forced remote stop');
    expect(Date.now() - startedAt).toBeLessThan(500);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it('rejects a late remote result after cancellation', async () => {
    let resolveFetch!: (value: Response) => void;
    const fetchImpl = vi.fn(
      () =>
        new Promise<Response>((resolve) => {
          resolveFetch = resolve;
        }),
    );
    const controller = new AbortController();
    const running = fetchWithAuth(
      'https://remote.invalid/action',
      { signal: controller.signal },
      0,
      { fetch: fetchImpl as typeof fetch, getAuthHeader: auth },
    );
    await vi.waitFor(() => expect(fetchImpl).toHaveBeenCalledTimes(1));

    controller.abort(new Error('cancelled remote generation'));
    resolveFetch(response({ unsafeLateResult: true }));

    await expect(running).rejects.toThrow('cancelled remote generation');
  });

  it('allows a fresh remote operation after an aborted pre-restart request', async () => {
    const staleController = new AbortController();
    const staleFetch = vi.fn(
      (_url: string | URL | Request, init?: RequestInit) =>
        new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener(
            'abort',
            () => reject(init.signal?.reason),
            { once: true },
          );
        }),
    );
    const stale = fetchWithAuth(
      'https://remote.invalid/stale',
      { signal: staleController.signal },
      0,
      { fetch: staleFetch as typeof fetch, getAuthHeader: auth },
    );
    staleController.abort(new Error('stale remote run'));
    await expect(stale).rejects.toThrow('stale remote run');

    const freshFetch = vi.fn(async () => response({ recovered: true }));
    await expect(
      fetchWithAuth('https://remote.invalid/fresh', {}, 0, {
        fetch: freshFetch as typeof fetch,
        getAuthHeader: auth,
      }),
    ).resolves.toEqual({ recovered: true });
  });
});
