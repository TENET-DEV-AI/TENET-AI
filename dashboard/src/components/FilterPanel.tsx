import { useState } from 'react';
import type { FilterState } from '../types/security';
import { DAYS_OF_WEEK, threatTypeLabel } from '../constants/charts';
import type { ExportFormat } from '../utils/exportEvents';

export interface Preset {
  name: string;
  filters: FilterState;
}

interface FilterPanelProps {
  filters: FilterState;
  detectionTypes: string[];
  threatTypes: string[];
  presets: Preset[];
  onUpdate: (key: keyof FilterState, value: string) => void;
  onClear: () => void;
  onSavePreset: (name: string) => void;
  onApplyPreset: (preset: Preset) => void;
  onDeletePreset: (index: number) => void;
  onExport: (format: ExportFormat) => void;
  resultCount: number;
}

const VERDICTS = ['malicious', 'suspicious', 'benign'];
const STATUSES = ['blocked', 'allowed'];
const ALERT_STATUSES = ['new', 'acknowledged', 'resolved'];

export function FilterPanel({
  filters,
  detectionTypes,
  threatTypes,
  presets,
  onUpdate,
  onClear,
  onSavePreset,
  onApplyPreset,
  onDeletePreset,
  onExport,
  resultCount,
}: FilterPanelProps) {
  const [presetName, setPresetName] = useState('');

  return (
    <div className="fpanel" aria-label="Filters">
      <div className="fhead">
        <span className="lbl">Filters · {resultCount} matching</span>
        <button className="abtn" onClick={onClear}>
          Clear all
        </button>
        <div className="qtools">
          <span className="lbl">Export</span>
          <button className="abtn" onClick={() => onExport('csv')}>
            CSV
          </button>
          <button className="abtn" onClick={() => onExport('json')}>
            JSON
          </button>
          <button className="abtn" onClick={() => onExport('pdf')}>
            Report
          </button>
        </div>
      </div>

      <div className="field wide">
        <label htmlFor="f-search">Search prompt, source or event id</label>
        <input
          id="f-search"
          value={filters.search}
          onChange={e => onUpdate('search', e.target.value)}
          placeholder="e.g. ignore all previous instructions"
        />
      </div>

      <div className="field">
        <label htmlFor="f-verdict">Verdict</label>
        <select id="f-verdict" value={filters.verdict} onChange={e => onUpdate('verdict', e.target.value)}>
          <option value="">Any</option>
          {VERDICTS.map(v => (
            <option key={v} value={v}>
              {v}
            </option>
          ))}
        </select>
      </div>

      <div className="field">
        <label htmlFor="f-status">Enforcement</label>
        <select id="f-status" value={filters.status} onChange={e => onUpdate('status', e.target.value)}>
          <option value="">Any</option>
          {STATUSES.map(s => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
      </div>

      <div className="field">
        <label htmlFor="f-alert">Workflow</label>
        <select
          id="f-alert"
          data-testid="filter-alert-status-select"
          value={filters.alertStatus ?? ''}
          onChange={e => onUpdate('alertStatus', e.target.value)}
        >
          <option value="">Any</option>
          {ALERT_STATUSES.map(s => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
      </div>

      <div className="field">
        <label htmlFor="f-threat">Threat type</label>
        <select id="f-threat" value={filters.threatType} onChange={e => onUpdate('threatType', e.target.value)}>
          <option value="">Any</option>
          {threatTypes.map(t => (
            <option key={t} value={t}>
              {threatTypeLabel(t)}
            </option>
          ))}
        </select>
      </div>

      <div className="field">
        <label htmlFor="f-type">Source type</label>
        <select id="f-type" value={filters.detectionType} onChange={e => onUpdate('detectionType', e.target.value)}>
          <option value="">Any</option>
          {detectionTypes.map(t => (
            <option key={t} value={t}>
              {t}
            </option>
          ))}
        </select>
      </div>

      <div className="field">
        <label htmlFor="f-source">Source id</label>
        <input
          id="f-source"
          value={filters.sourceIP}
          onChange={e => onUpdate('sourceIP', e.target.value)}
          placeholder="worker-02"
        />
      </div>

      <div className="field">
        <label htmlFor="f-from">From</label>
        <input id="f-from" type="date" value={filters.dateFrom} onChange={e => onUpdate('dateFrom', e.target.value)} />
      </div>

      <div className="field">
        <label htmlFor="f-to">To</label>
        <input id="f-to" type="date" value={filters.dateTo} onChange={e => onUpdate('dateTo', e.target.value)} />
      </div>

      <div className="field">
        <label htmlFor="f-day">Day of week</label>
        <select id="f-day" value={filters.dayOfWeek} onChange={e => onUpdate('dayOfWeek', e.target.value)}>
          <option value="">Any</option>
          {DAYS_OF_WEEK.map((day, index) => (
            <option key={day} value={String(index)}>
              {day}
            </option>
          ))}
        </select>
      </div>

      <div className="field">
        <label htmlFor="f-hour-from">Hour from</label>
        <input
          id="f-hour-from"
          type="number"
          min={0}
          max={23}
          value={filters.hourFrom}
          onChange={e => onUpdate('hourFrom', e.target.value)}
          placeholder="0"
        />
      </div>

      <div className="field">
        <label htmlFor="f-hour-to">Hour to</label>
        <input
          id="f-hour-to"
          type="number"
          min={0}
          max={23}
          value={filters.hourTo}
          onChange={e => onUpdate('hourTo', e.target.value)}
          placeholder="23"
        />
      </div>

      <div className="field wide">
        <label htmlFor="f-preset">Saved views</label>
        <div style={{ display: 'flex', gap: 6 }}>
          <input
            id="f-preset"
            value={presetName}
            onChange={e => setPresetName(e.target.value)}
            placeholder="Name this view"
          />
          <button
            className="abtn"
            onClick={() => {
              if (!presetName.trim()) return;
              onSavePreset(presetName.trim());
              setPresetName('');
            }}
          >
            Save
          </button>
        </div>
        {presets.length > 0 && (
          <div className="presetbar" style={{ padding: '6px 0 0', border: 0 }}>
            {presets.map((preset, index) => (
              <span className="chip" key={`${preset.name}-${index}`}>
                <button onClick={() => onApplyPreset(preset)} style={{ color: 'inherit' }}>
                  {preset.name}
                </button>
                <button onClick={() => onDeletePreset(index)} aria-label={`Delete ${preset.name}`}>
                  ×
                </button>
              </span>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
