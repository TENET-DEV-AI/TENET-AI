/** Where the console talks to the ingest service, and with which key. */
export const API_BASE = 'http://localhost:8000';

/**
 * Sent as `X-API-Key`. Vite inlines this into the browser bundle, so it is public
 * to anyone who loads the console — treat the dev console as a trusted-network
 * tool and never deploy it with a production key.
 */
export const API_KEY = import.meta.env.VITE_API_KEY || '';
