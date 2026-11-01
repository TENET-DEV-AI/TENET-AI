/** Okabe–Ito color-blind safe palette */
export const CB_PALETTE = [
  '#56B4E9',
  '#E69F00',
  '#009E73',
  '#F0E442',
  '#0072B2',
  '#D55E00',
  '#CC79A7',
  '#999999',
] as const;

export const SEVERITY_COLORS: Record<string, string> = {
  malicious: '#D55E00',
  suspicious: '#E69F00',
  benign: '#009E73',
};

export const THREAT_TYPE_LABELS: Record<string, string> = {
  prompt_injection: 'Prompt Injection',
  jailbreak: 'Jailbreak',
  data_extraction: 'Data Extraction',
  phishing: 'Phishing',
  role_manipulation: 'Role Manipulation',
  behavioral_multi_turn: 'Behavioral: Multi-Turn Probing',
  behavioral_risk_spike: 'Behavioral: Risk Spike',
  behavioral_coordinated: 'Behavioral: Coordinated Attack',
  behavioral_novelty: 'Behavioral: Novelty Anomaly',
  benign: 'Benign',
  unknown: 'Unknown',
};

export const DAYS_OF_WEEK = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'] as const;

export const HOUR_LABELS = Array.from({ length: 24 }, (_, i) =>
  `${i.toString().padStart(2, '0')}:00`
);

export function threatTypeLabel(key: string): string {
  return THREAT_TYPE_LABELS[key] ?? key.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}

export function colorForIndex(index: number): string {
  return CB_PALETTE[index % CB_PALETTE.length];
}
