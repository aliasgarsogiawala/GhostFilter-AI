// VirusTotal v3 lookups — read-only reputation checks. We never upload file
// content or submit arbitrary user data for public scanning; file checks are
// hash-only (see checkFileHash) so we never send someone's actual attachment
// bytes to a third party.

const VT_BASE = "https://www.virustotal.com/api/v3";

function getApiKey(): string {
  const key = process.env.VIRUSTOTAL_API_KEY;
  if (!key) throw new Error("VIRUSTOTAL_API_KEY is not set");
  return key;
}

interface LastAnalysisStats {
  malicious?: number;
  suspicious?: number;
  harmless?: number;
  undetected?: number;
}

export interface DomainReputation {
  domain: string;
  malicious: number;
  suspicious: number;
  harmless: number;
  undetected: number;
  reputation: number;
}

/** Domain-level reputation — synchronous, no submission/polling needed. */
export async function checkDomainReputation(domain: string): Promise<DomainReputation | null> {
  try {
    const res = await fetch(`${VT_BASE}/domains/${encodeURIComponent(domain)}`, {
      headers: { "x-apikey": getApiKey() },
    });
    if (!res.ok) return null;
    const json = await res.json();
    const stats: LastAnalysisStats = json?.data?.attributes?.last_analysis_stats ?? {};
    return {
      domain,
      malicious: stats.malicious ?? 0,
      suspicious: stats.suspicious ?? 0,
      harmless: stats.harmless ?? 0,
      undetected: stats.undetected ?? 0,
      reputation: json?.data?.attributes?.reputation ?? 0,
    };
  } catch {
    return null;
  }
}

export interface FileReputation {
  found: boolean;
  malicious: number;
  suspicious: number;
  harmless: number;
}

/** Looks up a file by its SHA-256 hash only — we never upload the file itself. */
export async function checkFileHash(sha256: string): Promise<FileReputation> {
  try {
    const res = await fetch(`${VT_BASE}/files/${sha256}`, {
      headers: { "x-apikey": getApiKey() },
    });
    if (!res.ok) return { found: false, malicious: 0, suspicious: 0, harmless: 0 };
    const json = await res.json();
    const stats: LastAnalysisStats = json?.data?.attributes?.last_analysis_stats ?? {};
    return {
      found: true,
      malicious: stats.malicious ?? 0,
      suspicious: stats.suspicious ?? 0,
      harmless: stats.harmless ?? 0,
    };
  } catch {
    return { found: false, malicious: 0, suspicious: 0, harmless: 0 };
  }
}
