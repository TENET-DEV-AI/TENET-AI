import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';
import axios from 'axios';
import type { SecurityEvent, Stats } from '../types/security';
import {
  createRefreshCoordinator,
  DEFAULT_REQUEST_TIMEOUT_MS,
  fetchDashboardSnapshot,
  preserveAlertState,
  type DashboardSnapshot,
} from './dashboardRefresh';

const health = { ingest: true, analyzer: true };
const snap = (n: number): DashboardSnapshot => ({ events: [], stats: { total_events: n } as Stats, health });

function deferred<T>() {
  let resolve!: (v: T) => void;
  let reject!: (e: unknown) => void;
  const promise = new Promise<T>((res, rej) => { resolve = res; reject = rej; });
  return { promise, resolve, reject };
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
  it('logs an unexpected failure but not an aborted refresh, and keeps the previous data', async () => {
    const error = vi.spyOn(console, 'error').mockImplementation(() => {});
    const onData = vi.fn();
    const failing = createRefreshCoordinator(() => Promise.reject(new Error('boom')), { onLoading: vi.fn(), onData });
    await failing.refresh();
    expect(error).toHaveBeenCalledTimes(1);
    expect(onData).not.toHaveBeenCalled();
    error.mockClear();
    const t = setup();
    const first = t.refresh();
    t.refresh();
    t.calls[0].d.resolve(snap(1));
    await first;
    expect(error).not.toHaveBeenCalled();
    error.mockRestore();
  });

  it('does not log or call handlers when a superseded request rejects after being aborted', async () => {
    const error = vi.spyOn(console, 'error').mockImplementation(() => {});
    const t = setup();
    const first = t.refresh();
    const second = t.refresh();
    expect(t.calls[0].signal.aborted).toBe(true);
    t.calls[0].d.reject(new Error('canceled'));
    await first;
    expect(error).not.toHaveBeenCalled();
    expect(t.onData).not.toHaveBeenCalled();
    t.calls[1].d.resolve(snap(2));
    await second;
    expect(t.onData).toHaveBeenCalledTimes(1);
    error.mockRestore();
  });

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

    it('a poll tick during an in-flight request does not abort it and the response is applied', async () => {
      const t = setup();
      const id = setInterval(t.poll, 10000);
      t.refresh();
      vi.advanceTimersByTime(30000);
      expect(t.calls).toHaveLength(1);
      expect(t.calls[0].signal.aborted).toBe(false);
      t.calls[0].d.resolve(snap(1));
      await vi.advanceTimersByTimeAsync(0);
      expect(t.onData).toHaveBeenCalledWith(snap(1));
      expect(t.onLoading).toHaveBeenLastCalledWith(false);
      vi.advanceTimersByTime(10000);
      expect(t.calls).toHaveLength(2);
      clearInterval(id);
    });

    it('a manual refresh still supersedes an in-flight poll', async () => {
      const t = setup();
      t.poll();
      t.refresh();
      expect(t.calls).toHaveLength(2);
      expect(t.calls[0].signal.aborted).toBe(true);
      t.calls[1].d.resolve(snap(2));
      t.calls[0].d.resolve(snap(1));
      await vi.advanceTimersByTimeAsync(0);
      expect(t.onData).toHaveBeenCalledTimes(1);
      expect(t.onData).toHaveBeenCalledWith(snap(2));
    });

    it('stop() drops a late response and never applies it', async () => {
      const t = setup();
      t.poll();
      t.stop();
      expect(t.calls[0].signal.aborted).toBe(true);
      t.calls[0].d.resolve(snap(1));
      await vi.advanceTimersByTimeAsync(0);
      expect(t.onData).not.toHaveBeenCalled();
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

  it('gives every request a timeout below the 10 s poll interval, or the one it is configured with', async () => {
    const spy = vi.spyOn(axios, 'get').mockResolvedValue({ data: { events: [] }, status: 200 });
    await fetchDashboardSnapshot(cfg, new AbortController().signal);
    spy.mock.calls.forEach(call => expect((call[1] as { timeout: number }).timeout).toBe(DEFAULT_REQUEST_TIMEOUT_MS));
    expect(DEFAULT_REQUEST_TIMEOUT_MS).toBeLessThan(10000);
    spy.mockClear();
    await fetchDashboardSnapshot({ ...cfg, timeoutMs: 1234 }, new AbortController().signal);
    expect(spy).toHaveBeenCalledTimes(4);
    spy.mock.calls.forEach(call => expect((call[1] as { timeout: number }).timeout).toBe(1234));
  });

  it('still returns stats and health when the events response has no body', async () => {
    vi.spyOn(axios, 'get').mockImplementation(async (url: string) => {
      if (url.endsWith('/v1/events')) return { data: null, status: 200 };
      if (url.endsWith('/v1/stats')) return { data: { total_events: 9 }, status: 200 };
      return { data: {}, status: 200 };
    });
    const out = await fetchDashboardSnapshot(cfg, new AbortController().signal);
    expect(out.events).toBeUndefined();
    expect(out.stats).toEqual({ total_events: 9 });
    expect(out.health).toEqual({ ingest: true, analyzer: true });
  });

  it('passes the abort signal to every request', async () => {
    const spy = vi.spyOn(axios, 'get').mockResolvedValue({ data: { events: [] }, status: 200 });
    const signal = new AbortController().signal;
    await fetchDashboardSnapshot(cfg, signal);
    expect(spy).toHaveBeenCalledTimes(4);
    spy.mock.calls.forEach(call => expect((call[1] as { signal: AbortSignal }).signal).toBe(signal));
  });
});

describe('preserveAlertState', () => {
  const ev = (id: string, extra: Partial<SecurityEvent> = {}) => ({ event_id: id, ...extra }) as SecurityEvent;

  it('keeps the status an analyst set when the backend sends the event without one', () => {
    const previous = [ev('a', { alert_status: 'acknowledged', acknowledged_at: '2026-11-01T10:00:00Z' })];
    const [merged] = preserveAlertState(previous, [ev('a')]);
    expect(merged.alert_status).toBe('acknowledged');
    expect(merged.acknowledged_at).toBe('2026-11-01T10:00:00Z');
  });

  it('keeps a resolution with its time and note', () => {
    const previous = [ev('a', { alert_status: 'resolved', resolved_at: '2026-11-01T11:00:00Z', resolution_note: 'false positive' })];
    const [merged] = preserveAlertState(previous, [ev('a')]);
    expect(merged).toMatchObject({ alert_status: 'resolved', resolved_at: '2026-11-01T11:00:00Z', resolution_note: 'false positive' });
  });

  it('lets a status from the backend win over the local one', () => {
    const previous = [ev('a', { alert_status: 'acknowledged' })];
    const [merged] = preserveAlertState(previous, [ev('a', { alert_status: 'resolved' })]);
    expect(merged.alert_status).toBe('resolved');
  });

  it('returns the backend list: new events are added and events the backend dropped are gone', () => {
    const previous = [ev('old', { alert_status: 'acknowledged' }), ev('keep', { alert_status: 'resolved' })];
    const merged = preserveAlertState(previous, [ev('keep'), ev('new')]);
    expect(merged.map(e => e.event_id)).toEqual(['keep', 'new']);
    expect(merged[0].alert_status).toBe('resolved');
    expect(merged[1].alert_status).toBeUndefined();
  });

  it('does not change the lists it is given', () => {
    const previous = [ev('a', { alert_status: 'acknowledged' })];
    const fetched = [ev('a')];
    preserveAlertState(previous, fetched);
    expect(fetched[0].alert_status).toBeUndefined();
    expect(previous[0].alert_status).toBe('acknowledged');
  });
});
