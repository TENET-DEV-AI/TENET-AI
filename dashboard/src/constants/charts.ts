/** Okabe–Ito color-blind safe palette */
export const CB_PALETTE = [
  '#E1593C',
  '#D9A441',
  '#8FA68E',
  '#C9BFA9',
  '#B4643F',
  '#EFE9DD',
  '#A87C5B',
  '#6E6A62',
] as const;

export const SEVERITY_COLORS: Record<string, string> = {
  malicious: '#E1593C',
  suspicious: '#D9A441',
  benign: '#8FA68E',
};

export const THREAT_TYPE_LABELS: Record<string, string> = {
  prompt_injection: 'Prompt Injection',
  jailbreak: 'Jailbreak',
  data_extraction: 'Data Extraction',
  phishing: 'Phishing',
  role_manipulation: 'Role Manipulation',
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
