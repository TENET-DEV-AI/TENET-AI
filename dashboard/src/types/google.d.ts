/**
 * Minimal typings for Google Identity Services (`accounts.google.com/gsi/client`).
 * Only the surface this console touches is declared.
 */
interface GoogleCredentialResponse {
  credential: string;
  select_by?: string;
  clientId?: string;
}

interface GoogleButtonOptions {
  type?: 'standard' | 'icon';
  theme?: 'outline' | 'filled_blue' | 'filled_black';
  size?: 'large' | 'medium' | 'small';
  text?: 'signin_with' | 'signup_with' | 'continue_with' | 'signin';
  shape?: 'rectangular' | 'pill' | 'circle' | 'square';
  logo_alignment?: 'left' | 'center';
  width?: number | string;
  locale?: string;
}

interface GoogleIdentityServices {
  accounts: {
    id: {
      initialize: (config: {
        client_id: string;
        callback: (response: GoogleCredentialResponse) => void;
        auto_select?: boolean;
        cancel_on_tap_outside?: boolean;
        use_fedcm_for_prompt?: boolean;
        ux_mode?: 'popup' | 'redirect';
      }) => void;
      renderButton: (parent: HTMLElement, options: GoogleButtonOptions) => void;
      disableAutoSelect: () => void;
      cancel: () => void;
      prompt: () => void;
    };
  };
}

interface Window {
  google?: GoogleIdentityServices;
}
