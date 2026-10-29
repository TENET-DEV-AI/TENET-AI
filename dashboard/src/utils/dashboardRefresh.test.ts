import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';
import axios from 'axios';
import {
  createRefreshCoordinator,
  fetchDashboardSnapshot,
  type DashboardSnapshot,
} from './dashboardRefresh';

const health = { ingest: true, analyzer: true };
const snap = (n: number): DashboardSnapshot => ({ events: [], stats: { n }, health });

function deferred<T>() {
  let resolve!: (v: T) => void;
  const promise = new Promise<T>(r => { resolve = r; });
  return { promise, resolve };
}

function setup() {
  const calls: { signal: AbortSignal; d: ReturnType<typeof deferred<DashboardSnapshot>> }[] = [];
  const load = vi.fn((signal: AbortSignal) => {
    const d = deferred<DashboardSnapshot>();
    calls.push({ signal, d });
    return d.promise;
  });
  const onLoading = vi.fn();
  const onData = vi.fn();
  const c = createRefreshCoordinator(load, { onLoading, onData });
  return { calls, load, onLoading, onData, ...c };
}

describe('createRefreshCoordinator', () => {
  it('ignores a stale response that resolves after a newer one', async () => {
    const t = setup();
    const first = t.refresh();
    const second = t.refresh();
    t.calls[1].d.resolve(snap(2));
    await second;
    t.calls[0].d.resolve(snap(1));
    await first;
    expect(t.onData).toHaveBeenCalledTimes(1);
    expect(t.onData).toHaveBeenCalledWith(snap(2));
  });

  it('aborts the previous request when a new refresh starts', async () => {
    const t = setup();
    const first = t.refresh();
    expect(t.calls[0].signal.aborted).toBe(false);
    const second = t.refresh();
    expect(t.calls[0].signal.aborted).toBe(true);
    t.calls[0].d.resolve(snap(1));
    t.calls[1].d.resolve(snap(2));
    await Promise.all([first, second]);
  });

  it('keeps loading true until the latest refresh finishes', async () => {
    const t = setup();
    const first = t.refresh();
    const second = t.refresh();
    t.calls[0].d.resolve(snap(1));
    await first;
    expect(t.onLoading).not.toHaveBeenCalledWith(false);
    t.calls[1].d.resolve(snap(2));
    await second;
    expect(t.onLoading).toHaveBeenLastCalledWith(false);
  });

  it('allows repeated manual refreshes and only the last one applies', async () => {
    const t = setup();
    const runs = [t.refresh(), t.refresh(), t.refresh()];
    expect(t.load).toHaveBeenCalledTimes(3);
    t.calls.forEach((c, i) => c.d.resolve(snap(i)));
    await Promise.all(runs);
    expect(t.onData).toHaveBeenCalledTimes(1);
    expect(t.onData).toHaveBeenCalledWith(snap(2));
  });

  it('does not call handlers after stop (unmount)', async () => {
    const t = setup();
    const run = t.refresh();
    t.onLoading.mockClear();
    t.stop();
    expect(t.calls[0].signal.aborted).toBe(true);
    t.calls[0].d.resolve(snap(1));
    await run;
    expect(t.onData).not.toHaveBeenCalled();
    expect(t.onLoading).not.toHaveBeenCalled();
  });

  it('swallows a rejected load and still clears loading', async () => {
    const onLoading = vi.fn();
    const onData = vi.fn();
    const c = createRefreshCoordinator(() => Promise.reject(new Error('x')), { onLoading, onData });
    await c.refresh();
    expect(onData).not.toHaveBeenCalled();
    expect(onLoading).toHaveBeenLastCalledWith(false);
  });

  describe('with fake timers', () => {
    beforeEach(() => { vi.useFakeTimers(); });
    afterEach(() => { vi.useRealTimers(); });

    it('a slow poll is superseded by the next interval tick', async () => {
      const t = setup();
      const id = setInterval(t.refresh, 10000);
      t.refresh();
      vi.advanceTimersByTime(10000);
      expect(t.calls).toHaveLength(2);
      expect(t.calls[0].signal.aborted).toBe(true);
      t.calls[1].d.resolve(snap(2));
      t.calls[0].d.resolve(snap(1));
      await vi.advanceTimersByTimeAsync(0);
      expect(t.onData).toHaveBeenCalledTimes(1);
      expect(t.onData).toHaveBeenCalledWith(snap(2));
      clearInterval(id);
    });
  });
});

describe('fetchDashboardSnapshot', () => {
  const cfg = { apiBase: 'http://api', apiKey: 'k', analyzerHealthUrl: 'http://an/health' };

  afterEach(() => { vi.restoreAllMocks(); });

  it('keeps other results when one endpoint fails', async () => {
    vi.spyOn(axios, 'get').mockImplementation(async (url: string) => {
      if (url.endsWith('/v1/events')) throw new Error('down');
      if (url.endsWith('/v1/stats')) return { data: { total_events: 5 }, status: 200 };
      if (url === 'http://an/health') throw new Error('down');
      return { data: {}, status: 200 };
    });
    const out = await fetchDashboardSnapshot(cfg, new AbortController().signal);
    expect(out.events).toBeUndefined();
    expect(out.stats).toEqual({ total_events: 5 });
    expect(out.health).toEqual({ ingest: true, analyzer: false });
  });

  it('passes the abort signal to every request', async () => {
    const spy = vi.spyOn(axios, 'get').mockResolvedValue({ data: { events: [] }, status: 200 });
    const signal = new AbortController().signal;
    await fetchDashboardSnapshot(cfg, signal);
    expect(spy).toHaveBeenCalledTimes(4);
    spy.mock.calls.forEach(call => expect((call[1] as { signal: AbortSignal }).signal).toBe(signal));
  });
});
