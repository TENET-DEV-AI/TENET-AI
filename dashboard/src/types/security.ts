export type Verdict = 'benign' | 'suspicious' | 'malicious';

export interface SecurityEvent {
  event_id: string;
  timestamp: string;
  source_type: string;
  source_id: string;
  model: string;
  prompt: string;
  verdict: Verdict;
  risk_score: number;
  blocked: boolean;
  threat_type?: string;
  org_id?: string;
  metadata?: {
    is_behavioral_alert?: boolean;
    detector_type?: string;
    detection_reason?: string;
    severity?: string;
    time_window_seconds?: number;
    contributing_events?: string[];
    shared_pattern?: string;
    participating_sources?: string[];
    [key: string]: any;
  };
  analysis_details?: Record<string, any>;
}

export interface Stats {
  total_events: number;
  blocked_count: number;
  threat_distribution: { malicious: number; suspicious: number; benign: number };
}

export interface FilterState {
  search: string;
  verdict: string;
  status: string;
  sourceIP: string;
  detectionType: string;
  threatType: string;
  dateFrom: string;
  dateTo: string;
  dayOfWeek: string;
  hourFrom: string;
  hourTo: string;
}

export type TimeRange = 'hourly' | 'daily' | 'weekly';

export interface ChartFilterAction {
  verdict?: string;
  threatType?: string;
  dateFrom?: string;
  dateTo?: string;
  dayOfWeek?: string;
  hourFrom?: string;
  hourTo?: string;
}
