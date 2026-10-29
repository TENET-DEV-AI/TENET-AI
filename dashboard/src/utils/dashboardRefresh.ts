import axios from 'axios';
import type { SecurityEvent } from '../types/security';

export interface DashboardSnapshot {
  /** undefined when the events request failed, so the caller keeps its previous value */
  events?: SecurityEvent[];
  /** undefined when the stats request failed or returned nothing */
  stats?: unknown;
  health: { ingest: boolean; analyzer: boolean };
}

export interface RefreshConfig {
  apiBase: string;
  apiKey: string;
  analyzerHealthUrl: string;
}

export async function fetchDashboardSnapshot(
  cfg: RefreshConfig,
  signal: AbortSignal,
): Promise<DashboardSnapshot> {
  const config = { headers: { 'X-API-Key': cfg.apiKey }, signal };
  const [eventsRes, statsRes, ingestHealth, analyzerHealth] = await Promise.allSettled([
    axios.get(`${cfg.apiBase}/v1/events`, config),
    axios.get(`${cfg.apiBase}/v1/stats`, config),
    axios.get(`${cfg.apiBase}/health`, { signal }),
    axios.get(cfg.analyzerHealthUrl, { signal }),
  ]);
  return {
    events:
      eventsRes.status === 'fulfilled'
        ? Array.isArray(eventsRes.value.data.events) ? eventsRes.value.data.events : []
        : undefined,
    stats: statsRes.status === 'fulfilled' ? statsRes.value.data || undefined : undefined,
    health: {
      ingest: ingestHealth.status === 'fulfilled' && ingestHealth.value.status === 200,
      analyzer: analyzerHealth.status === 'fulfilled' && analyzerHealth.value.status === 200,
    },
  };
}

export interface RefreshHandlers {
  onLoading: (loading: boolean) => void;
  onData: (snapshot: DashboardSnapshot) => void;
}

/**
 * Runs dashboard refreshes so that only the most recent one can touch state.
 * Starting a new refresh aborts the previous request; stop() aborts everything
 * (used on unmount). A superseded or stopped refresh never calls the handlers.
 */
export function createRefreshCoordinator(
  load: (signal: AbortSignal) => Promise<DashboardSnapshot>,
  handlers: RefreshHandlers,
) {
  let generation = 0;
  let controller: AbortController | null = null;

  const refresh = async () => {
    controller?.abort();
    const current = ++generation;
    const own = new AbortController();
    controller = own;
    handlers.onLoading(true);
    try {
      const snapshot = await load(own.signal);
      if (current === generation && !own.signal.aborted) handlers.onData(snapshot);
    } catch {
      /* aborted or unexpected failure: keep the previous data */
    } finally {
      if (current === generation && !own.signal.aborted) handlers.onLoading(false);
    }
  };

  const stop = () => {
    generation++;
    controller?.abort();
    controller = null;
  };

  return { refresh, stop };
}
