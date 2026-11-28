/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** API key sent to the ingest service as `X-API-Key`. Public to anyone who loads the console. */
  readonly VITE_API_KEY?: string;
  /** Google OAuth 2.0 web client id. When set, the console signs analysts in with Google. */
  readonly VITE_GOOGLE_CLIENT_ID?: string;
  /** "true" enables the credential form in a production build. Leave unset unless the API checks passwords. */
  readonly VITE_ALLOW_PASSWORD_AUTH?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
