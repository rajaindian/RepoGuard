export enum RiskCategory {
  DATA_EXFILTRATION = 'data_exfiltration',
  OBFUSCATION = 'obfuscation',
  INSTALL_SCRIPTS = 'install_scripts',
  BACKDOORS = 'backdoors',
  PRIVACY = 'privacy',
  DEPENDENCIES = 'dependencies',
  FILESYSTEM = 'filesystem',
  SUPPLY_CHAIN = 'supply_chain',
}

export enum Severity {
  LOW = 'LOW',
  MEDIUM = 'MEDIUM',
  HIGH = 'HIGH',
  CRITICAL = 'CRITICAL',
}

export enum Verdict {
  GREEN = 'GREEN',
  YELLOW = 'YELLOW',
  RED = 'RED',
}

export interface Finding {
  severity: Severity;
  category: RiskCategory;
  file: string;
  line: number;
  description: string;
  evidence: string;
  confidence: number; // 0-1
}

export interface CategoryScore {
  category: RiskCategory;
  score: number; // 0-10
  level: 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH';
  findings: Finding[];
}

export interface RepoMetadata {
  url?: string;
  localPath: string;
  stars?: number;
  age?: string; // ISO date of creation
  contributors?: number;
  isFork?: boolean;
  forkedFrom?: string;
  defaultBranch?: string;
}

export interface ScanResult {
  repoMetadata: RepoMetadata;
  findings: Finding[];
  categoryScores: CategoryScore[];
  verdict: Verdict;
  summary: string;
  recommendation: string;
  scanTimestamp: string;
  scanMode: 'strict' | 'relaxed';
  aiUsed: boolean;
}
