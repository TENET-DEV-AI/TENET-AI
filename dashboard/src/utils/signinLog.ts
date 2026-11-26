import axios from 'axios';
import { API_BASE, API_KEY } from '../config';

export type SignInProvider = 'google' | 'password';

export interface SignInStats {
  window_days: number;
  total: number;
  unique_accounts: number;
  by_day: { date: string; count: number }[];
  by_provider: Record<string, number>;
  last_signin: { email: string; provider: string; at: string; role?: string | null } | null;
}

const config = { headers: { 'X-API-Key': API_KEY }, timeout: 4000 };

/**
 * Appends one sign-in to the server-side log. Fire-and-forget on purpose: a
 * failed write must never stand between an analyst and the console.
 */
export async function recordSignIn(
  email: string,
  provider: SignInProvider,
  role?: string,
): Promise<void> {
  try {
    await axios.post(`${API_BASE}/v1/signins`, { email, provider, role }, config);
  } catch {
    /* logging is best-effort — the sign-in already succeeded */
  }
}

/** Counts for the console. Returns null when the API cannot answer. */
export async function fetchSignInStats(days = 7): Promise<SignInStats | null> {
  try {
    const { data } = await axios.get<SignInStats>(`${API_BASE}/v1/signins/stats`, {
      ...config,
      params: { days },
    });
    return data;
  } catch {
    return null;
  }
}
