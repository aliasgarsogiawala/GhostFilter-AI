export interface HighlightSegment {
  text: string;
  severity?: "amber" | "red";
}

interface Flag {
  phrase: string;
  severity: "amber" | "red";
}

/** Splits `text` into plain/highlighted segments covering it end-to-end, in order, no overlaps. */
export function buildHighlightSegments(text: string, flags: Flag[]): HighlightSegment[] {
  if (!flags.length || !text) return [{ text }];

  const lower = text.toLowerCase();
  const matches: { start: number; end: number; severity: "amber" | "red" }[] = [];

  for (const flag of flags) {
    const needle = flag.phrase.toLowerCase().trim();
    if (!needle) continue;
    const idx = lower.indexOf(needle);
    if (idx === -1) continue;
    matches.push({ start: idx, end: idx + needle.length, severity: flag.severity });
  }

  matches.sort((a, b) => a.start - b.start);

  const segments: HighlightSegment[] = [];
  let cursor = 0;
  for (const m of matches) {
    if (m.start < cursor) continue; // overlaps a previous match, skip
    if (m.start > cursor) segments.push({ text: text.slice(cursor, m.start) });
    segments.push({ text: text.slice(m.start, m.end), severity: m.severity });
    cursor = m.end;
  }
  if (cursor < text.length) segments.push({ text: text.slice(cursor) });

  return segments;
}
