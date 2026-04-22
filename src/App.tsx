import React, { useState, useEffect, useMemo, useRef } from 'react';
import { 
  Shield,
  Activity,
  Globe,
  Cpu,
  Zap, 
  ArrowUp, 
  ArrowDown, 
  Lock, 
  Unlock, 
  MoreVertical, 
  Search,
  Settings,
  Bell,
  HardDrive,
  Filter,
  ShieldOff,
  Trash2,
  Download,
  AlertTriangle
} from 'lucide-react';
import { 
  LineChart, 
  Line, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  ResponsiveContainer, 
  AreaChart,
  Area
} from 'recharts';
import { motion, AnimatePresence } from 'motion/react';
import { cn } from './lib/utils';
// Use explicit subpath for Tauri v2 compatibility
import { listen } from '@tauri-apps/api/event';
import { invoke } from '@tauri-apps/api/core';
import { GoogleGenAI, Type } from "@google/genai";

// --- AI Initialization (lazy — key loaded at runtime from config.json via Tauri) ---
let aiClient: GoogleGenAI | null = null;

async function getAiClient(): Promise<GoogleGenAI> {
  if (!aiClient) {
    const apiKey = await invoke<string>('get_api_key');
    aiClient = new GoogleGenAI({ apiKey });
  }
  return aiClient;
}

// --- GeoIP helpers ---
function buildLocationLabel(geo: { city?: string; region?: string; country_code?: string; asn?: string; org?: string }): string {
  const parts = [geo.city, geo.region, geo.country_code].filter(Boolean).join(', ');
  const suffix = geo.asn ? ` — ${geo.asn} ${geo.org}` : geo.org ? ` — ${geo.org}` : '';
  return parts ? `${parts}${suffix}` : (geo.org || '');
}

// --- Local fallback explanation (no API key required) ---
// Used when cloud AI is disabled or unavailable. Builds a human-readable
// assessment from GeoIP org/country, port semantics, and the heuristic reason.
function localExplain(ip: string, port: number, protocol: string, location: string, reason: string): string {
  const org = location.includes(' — ') ? location.split(' — ')[1]?.trim() : '';
  const country = (() => {
    const withoutOrg = location.split(' — ')[0].trim();
    const parts = withoutOrg.split(', ');
    return parts[parts.length - 1]?.trim() || '';
  })();

  const parts: string[] = [];

  if (org)     parts.push(org);
  if (country) parts.push(`located in ${country}`);

  const portDesc: Record<number, string> = {
    80: 'HTTP (unencrypted web)', 443: 'HTTPS', 53: 'DNS',
    22: 'SSH — review if unexpected', 25: 'SMTP mail relay',
    3389: 'RDP remote desktop — high risk if external', 445: 'SMB file sharing — block if external',
    6667: 'IRC (exploit/C2 channel)', 4444: 'Metasploit default — likely exploit traffic',
    31337: 'Elite/back-orifice port — likely malicious',
  };
  parts.push(portDesc[port] ?? `port ${port} (${protocol})`);

  if (reason.includes('Beaconing'))
    parts.push('consistent intervals suggest a keepalive or background sync — verify the process is expected');
  if (reason.includes('Blacklisted'))
    parts.push('IP matches threat intelligence blacklist — block and investigate immediately');
  if (reason.includes('Protocol Mismatch'))
    parts.push('protocol mismatch may indicate tunneling or a misconfigured service');

  const highRiskCountries = ['Russia', 'RU', 'China', 'CN', 'North Korea', 'KP', 'Iran', 'IR', 'Belarus', 'BY'];
  if (highRiskCountries.some(c => country.includes(c)))
    parts.push('origin country has elevated threat profile — investigate if this connection is unexpected');

  // Check for residential vs cloud hosting to distinguish C2 from CDN
  const cloudKeywords = ['Amazon', 'Google', 'Microsoft', 'Azure', 'Cloudflare', 'Akamai', 'Fastly', 'DigitalOcean', 'Hetzner'];
  const isCloud = cloudKeywords.some(k => org.includes(k));
  if (isCloud && reason.includes('Beaconing'))
    parts.push('cloud-hosted endpoint — beaconing to cloud providers is common and usually benign');

  return parts.join(' · ') || `No local context available for ${ip} — manual review recommended.`;
}

// --- Types ---

interface GeoInfo {
  city: string;
  region: string;
  country_code: string;
  asn: string;
  org: string;
}

interface Connection {
  id: string;
  process: string;
  pid: number;
  remoteAddr: string;
  remotePort: number;
  download: number; // MB/s
  upload: number;   // MB/s
  status: 'safe' | 'suspicious' | 'blocked';
  protocol: string;
  location: string;
  geoInfo?: GeoInfo;
  threatLabel: string;
}

interface NetworkEvent {
  process: string;
  pid: number;
  remote_addr: string;
  remote_port: number;
  bytes: number;
  protocol: string;
  direction: string;
  threat_score: number;
  threat_label: string;
  geo_info?: GeoInfo;
}

interface FirewallRule {
  id: string;
  name: string;
  process: string;
  zone: 'Public' | 'Private' | 'Domain';
  action: 'Allow' | 'Block';
  direction: 'Inbound' | 'Outbound';
}

interface TrafficData {
  time: string;
  down: number;
  up: number;
}

const MOCK_CONNECTIONS: Connection[] = [];

const INITIAL_HISTORY: TrafficData[] = [];

interface InterfaceInfo {
  name: string;
  description: string;
  index: number;
}

export default function App() {
  const [activeTab, setActiveTab] = useState<'live' | 'firewall' | 'guardian' | 'settings' | 'notifications'>('live');
  const [connections, setConnections] = useState<Connection[]>(MOCK_CONNECTIONS);
  const [history, setHistory] = useState<TrafficData[]>(INITIAL_HISTORY);
  const [isGuardianActive, setIsGuardianActive] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [isDesktop, setIsDesktop] = useState(false);
  const [useCloudAi, setUseCloudAi] = useState(false);
  const [aiRequestCount, setAiRequestCount] = useState(0);
  const [aiQuotaError, setAiQuotaError] = useState<string | null>(null);
  const [captureError, setCaptureError] = useState<string | null>(null);
  const [notificationsEnabled, setNotificationsEnabled] = useState(true);
  const [aiAnalysis, setAiAnalysis] = useState<Record<string, string>>({});
  const [firewallRules, setFirewallRules] = useState<string[]>([]);
  const [availableInterfaces, setAvailableInterfaces] = useState<InterfaceInfo[]>([]);
  const [selectedInterface, setSelectedInterface] = useState<string>('');
  const [detections, setDetections] = useState<{
    id: string, 
    ip: string, 
    port: number, 
    protocol: string, 
    reason: string, 
    score: number, 
    time: string, 
    location: string, 
    geoInfo?: GeoInfo,
    aiNote: string | null
  }[]>([]);
  const [sortKey, setSortKey] = useState<keyof Connection | null>(null);
  const [groupSortKey, setGroupSortKey] = useState<'process' | 'pid' | 'endpoints' | 'dataRate' | null>(null);
  const [groupSortDir, setGroupSortDir] = useState<'asc' | 'desc'>('asc');
  const [sessionTotalDown, setSessionTotalDown] = useState(0); // In bytes
  const [sessionTotalUp, setSessionTotalUp] = useState(0);     // In bytes
  const [downRateMBps, setDownRateMBps] = useState(0);
  const [upRateMBps, setUpRateMBps] = useState(0);
  const sessionTotalDownRef = useRef(0);
  const sessionTotalUpRef = useRef(0);
  const geoCacheRef = useRef<Record<string, GeoInfo>>({});
  const detectionCooldownRef = useRef<Set<string>>(new Set());
  const useCloudAiRef = useRef(useCloudAi);
  const [isFilterOpen, setIsFilterOpen] = useState(false);
  const [filterType, setFilterType] = useState<'all' | 'suspicious' | 'blocked' | 'safe'>('all');
  const [monitoringMode, setMonitoringMode] = useState<'audit' | 'active'>('active');
  const [isPaused, setIsPaused] = useState(false);
  const isPausedRef = useRef(isPaused);
  const [expandedProcesses, setExpandedProcesses] = useState<Set<string>>(new Set());
  const [processTotals, setProcessTotals] = useState<Record<string, {downBytes: number, upBytes: number}>>({});
  const [aiTabAnalysis, setAiTabAnalysis] = useState<string | null>(null);
  const [aiTabAnalyzing, setAiTabAnalyzing] = useState(false);
  const [analyzingDetections, setAnalyzingDetections] = useState<Set<string>>(new Set());

  useEffect(() => {
    isPausedRef.current = isPaused;
  }, [isPaused]);

  useEffect(() => { useCloudAiRef.current = useCloudAi; }, [useCloudAi]);

  // 1-second ticker: compute MB/s rate from delta and advance the chart
  useEffect(() => {
    const prevRef = { down: 0, up: 0 };
    const interval = setInterval(() => {
      const currentDown = sessionTotalDownRef.current;
      const currentUp = sessionTotalUpRef.current;
      const downMBps = (currentDown - prevRef.down) / (1024 * 1024);
      const upMBps = (currentUp - prevRef.up) / (1024 * 1024);
      prevRef.down = currentDown;
      prevRef.up = currentUp;
      setDownRateMBps(downMBps);
      setUpRateMBps(upMBps);
      const label = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
      setHistory((prev: TrafficData[]) => [...prev.slice(-29), { time: label, down: parseFloat(downMBps.toFixed(4)), up: parseFloat(upMBps.toFixed(4)) }]);
    }, 1000);
    return () => clearInterval(interval);
  }, []);

  const filteredConnections = useMemo(() => {
    let result = connections.filter(c => 
      c.process.toLowerCase().includes(searchQuery.toLowerCase()) ||
      c.remoteAddr.includes(searchQuery) ||
      c.status.includes(searchQuery.toLowerCase())
    );

    if (sortKey) {
      result.sort((a, b) => {
        const valA = a[sortKey];
        const valB = b[sortKey];
        if (typeof valA === 'number' && typeof valB === 'number') return (valB as number) - (valA as number);
        if (typeof valA === 'string' && typeof valB === 'string') return (valA as string).localeCompare(valB as string);
        return 0;
      });
    }
    return result;
  }, [connections, searchQuery, sortKey]);

  const finalFilteredConnections = useMemo(() => {
    let result = filteredConnections;
    if (filterType !== 'all') {
      result = result.filter(c => c.status === filterType);
    }
    return result;
  }, [filteredConnections, filterType]);

  const groupedConnections = useMemo(() => {
    const groups: Record<string, {
      process: string,
      pid: number,
      connections: Connection[],
      totalDownload: number,
      totalUpload: number,
      totalDownBytes: number,
      totalUpBytes: number,
      status: string
    }> = {};

    finalFilteredConnections.forEach(conn => {
      if (!groups[conn.process]) {
        const pt = processTotals[conn.process] ?? { downBytes: 0, upBytes: 0 };
        groups[conn.process] = {
          process: conn.process,
          pid: conn.pid,
          connections: [],
          totalDownload: 0,
          totalUpload: 0,
          totalDownBytes: pt.downBytes,
          totalUpBytes: pt.upBytes,
          status: conn.status
        };
      }
      groups[conn.process].connections.push(conn);
      groups[conn.process].totalDownload += conn.download;
      groups[conn.process].totalUpload += conn.upload;
      if (conn.status === 'suspicious' || conn.status === 'blocked') {
        groups[conn.process].status = conn.status;
      }
    });

    const list = Object.values(groups);
    if (groupSortKey) {
      list.sort((a, b) => {
        let cmp = 0;
        if (groupSortKey === 'process') cmp = a.process.toLowerCase().localeCompare(b.process.toLowerCase());
        else if (groupSortKey === 'pid') cmp = a.pid - b.pid;
        else if (groupSortKey === 'endpoints') cmp = a.connections.length - b.connections.length;
        else if (groupSortKey === 'dataRate') cmp = (a.totalDownload + a.totalUpload) - (b.totalDownload + b.totalUpload);
        return groupSortDir === 'asc' ? cmp : -cmp;
      });
    }
    return list;
  }, [finalFilteredConnections, groupSortKey, groupSortDir, processTotals]);

  const handleGroupSort = (key: 'process' | 'pid' | 'endpoints' | 'dataRate') => {
    if (groupSortKey === key) setGroupSortDir(d => d === 'asc' ? 'desc' : 'asc');
    else { setGroupSortKey(key); setGroupSortDir('asc'); }
  };

  const SortArrow = ({ col }: { col: 'process' | 'pid' | 'endpoints' | 'dataRate' }) => (
    <span className="ml-1 inline-flex flex-col leading-none text-[8px]">
      <span className={groupSortKey === col && groupSortDir === 'asc' ? 'text-emerald-400' : 'text-slate-600'}>▲</span>
      <span className={groupSortKey === col && groupSortDir === 'desc' ? 'text-emerald-400' : 'text-slate-600'}>▼</span>
    </span>
  );

  const formatDataSize = (bytes: number) => {
    if (bytes === 0) return '0.00 MB';
    const mb = bytes / (1024 * 1024);
    if (mb < 0.01) return '0.00 MB';
    return mb.toFixed(2) + ' MB';
  };

  const formatRate = (rateMBps: number) => {
    return rateMBps.toFixed(2) + ' MB/s';
  };

  const csvTimestamp = () => new Date().toISOString().slice(0, 19).replace(/[T:]/g, '-');

  const exportDetectionsCsv = async (prefix: string) => {
    if (detections.length === 0) return;
    const filename = `${prefix}_${csvTimestamp()}.csv`;
    const headers = ['Time', 'IP Address', 'Port', 'Location', 'Threat Reason', 'Risk Score', 'AI Note'];
    const rows = detections.map(d => [d.time, d.ip, d.port || '', `"${d.location || ''}"`, `"${d.reason}"`, d.score, d.aiNote ? `"${d.aiNote}"` : '']);
    const csvContent = [headers, ...rows].map(e => e.join(",")).join("\n");

    if (isDesktop) {
      try {
        const res = await invoke<string>('save_traffic_csv', { csvData: csvContent, filename });
        alert(res);
      } catch (err) {
        console.error("Export failed:", err);
      }
    } else {
      const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.setAttribute("href", url);
      link.setAttribute("download", filename);
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);
    }
  };

  const exportToCsv = async () => {
    const filename = `vigilance_traffic_log_${csvTimestamp()}.csv`;
    const headers = ['Process', 'PID', 'Remote Address', 'Remote Port', 'Protocol', 'Status', 'Download (MB/s)', 'Upload (MB/s)'];
    const rows = finalFilteredConnections.map(c => [
      c.process,
      c.pid,
      c.remoteAddr,
      c.remotePort,
      c.protocol,
      c.status,
      c.download.toFixed(3),
      c.upload.toFixed(3)
    ]);

    const csvContent = [headers, ...rows].map(e => e.join(",")).join("\n");

    if (isDesktop) {
      try {
        const res = await invoke<string>('save_traffic_csv', { csvData: csvContent, filename });
        alert(res);
      } catch (err) {
        console.error("Export failed:", err);
      }
    } else {
      const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.setAttribute("href", url);
      link.setAttribute("download", filename);
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
    }
  };

  // Fetch initial system data
  useEffect(() => {
    async function init() {
      if ((window as any).__TAURI_INTERNALS__) {
        // Auto-disable cloud AI if the key is missing or unreadable
        try {
          await invoke<string>('get_api_key');
        } catch {
          setUseCloudAi(false);
        }

        try {
          const rules = await invoke<string[]>('get_firewall_rules');
          setFirewallRules(rules);
          const ifaces = await invoke<InterfaceInfo[]>('get_interfaces');
          setAvailableInterfaces(ifaces);
          if (ifaces.length > 0) {
            // Logic to find the best default interface (Wi-Fi or Ethernet usually preferred over Virtual)
            const preferred = ifaces.find(i => 
              i.description.toLowerCase().includes('wi-fi') || 
              i.description.toLowerCase().includes('wlan') || 
              i.description.toLowerCase().includes('ethernet') ||
              i.name.toLowerCase().includes('wlan') ||
              i.name.toLowerCase().includes('eth')
            );
            setSelectedInterface(preferred ? preferred.name : ifaces[0].name);
          }
        } catch (err) {
          console.error("Init fetch failed:", err);
        }
      }
    }
    init();
  }, []);

  // Handle interface change
  useEffect(() => {
    if (selectedInterface && isDesktop) {
      invoke('set_capture_interface', { name: selectedInterface })
        .catch(err => console.error("Switch failed:", err));
    }
  }, [selectedInterface, isDesktop]);

  const deleteRule = async (ip: string) => {
    try {
      if (isDesktop) {
        const result = await invoke<string>('delete_firewall_rule', { ip });
        setFirewallRules(prev => prev.filter(r => r !== ip));
        alert(result);
      }
    } catch (err) {
      alert(`Delete error: ${err}`);
    }
  };

  const blockConnection = async (ip: string) => {
    try {
      if (isDesktop) {
        const result = await invoke('block_ip', { ip });
        alert(result);
        setConnections(prev => prev.map(c => 
          c.remoteAddr === ip ? { ...c, status: 'blocked' } : c
        ));
      } else {
        alert(`Simulation: IP ${ip} blocked.`);
      }
    } catch (err) {
      alert(`Firewall Error: ${err}`);
    }
  };

  const analyzeCurrentTab = async () => {
    if (aiTabAnalyzing) return;
    setAiTabAnalyzing(true);
    setAiTabAnalysis(null);

    try {
      let prompt = '';

      if (activeTab === 'live') {
        const items = connections.slice(0, 25);
        if (items.length === 0) { setAiTabAnalysis('No active connections to analyze.'); setAiTabAnalyzing(false); return; }
        const summary = items.map(c =>
          `${c.process} → ${c.remoteAddr}:${c.remotePort} (${c.protocol}) [${c.status}]${c.location ? ` · ${c.location}` : ''}`
        ).join('\n');
        prompt = `You are a network security analyst. Analyze these ${items.length} active network connections and give a concise 2–3 sentence security assessment — flag anything unusual:\n${summary}`;
      } else if (activeTab === 'notifications' || activeTab === 'guardian') {
        if (detections.length === 0) { setAiTabAnalysis('No detections to analyze.'); setAiTabAnalyzing(false); return; }
        const items = detections.slice(0, 15);
        const summary = items.map(d =>
          `IP ${d.ip}:${d.port} (${d.protocol}) — ${d.reason} [score:${d.score}]${d.location ? ` · ${d.location}` : ''}`
        ).join('\n');
        prompt = `You are a network security analyst. Analyze these ${items.length} heuristic detections and provide a concise 2–3 sentence threat assessment. Identify any patterns or the most urgent risk:\n${summary}`;
      } else if (activeTab === 'firewall') {
        if (firewallRules.length === 0) { setAiTabAnalysis('No firewall rules to analyze.'); setAiTabAnalyzing(false); return; }
        prompt = `You are a network security analyst. These IPs are currently blocked in the firewall: ${firewallRules.join(', ')}. In 2–3 sentences, identify if any are well-known malicious ranges and assess the overall blocking policy.`;
      }

      if (!prompt) { setAiTabAnalyzing(false); return; }

      if (!useCloudAi) {
        setAiTabAnalysis('Enable Cloud AI in Settings to use tab analysis.');
        setAiTabAnalyzing(false);
        return;
      }

      const ai = await getAiClient();
      setAiRequestCount(prev => prev + 1);
      setAiQuotaError(null);
      const response = await ai.models.generateContent({ model: 'gemini-2.0-flash', contents: prompt });
      setAiTabAnalysis(response.text || 'Analysis complete.');
    } catch (err) {
      const msg = String(err);
      if (msg.includes('429') || msg.toLowerCase().includes('quota') || msg.toLowerCase().includes('rate limit')) {
        setAiQuotaError('Gemini quota exceeded — AI analysis unavailable until quota resets.');
        setAiTabAnalysis(null);
      } else {
        setAiTabAnalysis(`AI error: ${msg}`);
      }
    } finally {
      setAiTabAnalyzing(false);
    }
  };

  const analyzeDetection = async (det: { id: string; ip: string; port: number; protocol: string; reason: string; score: number; location: string }) => {
    if (analyzingDetections.has(det.id)) return;
    setAnalyzingDetections(prev => new Set(prev).add(det.id));
    try {
      let note: string;
      if (useCloudAi) {
        const ai = await getAiClient();
        setAiRequestCount(prev => prev + 1);
        setAiQuotaError(null);
        const response = await ai.models.generateContent({
          model: 'gemini-2.0-flash',
          contents: `Analyze this network security detection in 1–2 sentences. IP: ${det.ip}:${det.port} (${det.protocol}). Reason: ${det.reason} (risk score: ${det.score}).${det.location ? ` Location: ${det.location}.` : ''} Identify what this IP likely belongs to and whether it is a real threat.`
        });
        note = response.text || 'Analysis complete.';
      } else {
        note = localExplain(det.ip, det.port, det.protocol, det.location, det.reason);
      }
      setDetections(prev => prev.map(d => d.id === det.id ? { ...d, aiNote: note } : d));
    } catch (err) {
      const msg = String(err);
      if (msg.includes('429') || msg.toLowerCase().includes('quota') || msg.toLowerCase().includes('rate limit')) {
        setAiQuotaError('Gemini quota exceeded — AI analysis unavailable until quota resets.');
      } else {
        setDetections(prev => prev.map(d => d.id === det.id ? { ...d, aiNote: `AI error: ${msg}` } : d));
      }
    } finally {
      setAnalyzingDetections(prev => { const s = new Set(prev); s.delete(det.id); return s; });
    }
  };

  const analyzeThreat = async (conn: Connection) => {
    if (aiAnalysis[conn.id]) return;
    
    if (!useCloudAi) {
      setAiAnalysis(prev => ({ ...prev, [conn.id]: "Heuristic engine scan complete. Source verified." }));
      return;
    }
    
    try {
      const ai = await getAiClient();
      setAiRequestCount((prev: number) => prev + 1);
      setAiQuotaError(null);
      const response = await ai.models.generateContent({
        model: 'gemini-2.0-flash',
        contents: `Analyze this network connection and tell me if it looks like a threat or normal behavior: 
        Process: ${conn.process}, Remote IP: ${conn.remoteAddr}, Port: ${conn.remotePort}, Protocol: ${conn.protocol}. 
        Return a short 1-sentence assessment.`,
        config: {
          responseMimeType: "application/json",
          responseSchema: {
            type: Type.OBJECT,
            properties: {
              assessment: { type: Type.STRING },
              isThreat: { type: Type.BOOLEAN }
            },
            required: ["assessment", "isThreat"]
          }
        }
      });
      
      const result = JSON.parse(response.text || '{}');
      setAiAnalysis(prev => ({ ...prev, [conn.id]: result.assessment }));
      
      if (result.isThreat) {
        setConnections(prev => prev.map(c => 
          c.id === conn.id ? { ...c, status: 'suspicious' } : c
        ));
      }
    } catch (err) {
      const msg = String(err);
      if (msg.includes('429') || msg.toLowerCase().includes('quota') || msg.toLowerCase().includes('rate limit')) {
        setAiQuotaError('Gemini quota exceeded — AI analysis unavailable until quota resets.');
      } else {
        setAiQuotaError(`AI error: ${msg}`);
      }
      console.error("AI Analysis failed:", err);
    }
  };

  // Monitor for real-world network events from Tauri backend
  useEffect(() => {
    let unlisten: (() => void) | undefined;

    async function setupListener() {
      try {
        // Detect if we are running in the Tauri shell
        if ((window as any).__TAURI_INTERNALS__) {
          setIsDesktop(true);
          
          await listen<string>('capture-error', (event) => {
            setCaptureError(event.payload);
          });

          await listen<{ ip: string; geo: GeoInfo }>('geo-resolved', (event) => {
            const { ip, geo } = event.payload;
            geoCacheRef.current[ip] = geo;
            const label = buildLocationLabel(geo);
            setConnections(prev => prev.map(c =>
              c.remoteAddr === ip ? { ...c, location: label, geoInfo: geo } : c
            ));
            setDetections(prev => prev.map(d => {
              if (d.ip !== ip) return d;
              return { ...d, location: label, geoInfo: geo, aiNote: localExplain(d.ip, d.port, d.protocol, label, d.reason) };
            }));
          });

          unlisten = await listen<NetworkEvent>('network-event', (event) => {
            if (isPausedRef.current) return;
            const data = event.payload;
            
            // Update session cumulative totals
            if (data.direction === 'Inbound') {
              setSessionTotalDown(prev => { sessionTotalDownRef.current = prev + data.bytes; return prev + data.bytes; });
            } else {
              setSessionTotalUp(prev => { sessionTotalUpRef.current = prev + data.bytes; return prev + data.bytes; });
            }

            // Accumulate per-process totals
            const proc = data.process || 'Active App';
            setProcessTotals((prev: Record<string, {downBytes: number, upBytes: number}>) => {
              const entry = prev[proc] ?? { downBytes: 0, upBytes: 0 };
              return {
                ...prev,
                [proc]: {
                  downBytes: entry.downBytes + (data.direction === 'Inbound' ? data.bytes : 0),
                  upBytes: entry.upBytes + (data.direction === 'Outbound' ? data.bytes : 0),
                }
              };
            });

            // GeoIP: backend resolves asynchronously; cache on first arrival and backfill existing cards
            const geoIp = data.remote_addr;
            const backendGeo = data.geo_info;
            const alreadyCached = !!geoCacheRef.current[geoIp];

            if (backendGeo) {
              geoCacheRef.current[geoIp] = backendGeo;
            }
            const geoInfo: GeoInfo | undefined = geoCacheRef.current[geoIp];
            const locationLabel = geoInfo ? buildLocationLabel(geoInfo) : '';

            // First time geo resolves for this IP — backfill connections + detection cards
            if (backendGeo && !alreadyCached) {
              const label = buildLocationLabel(backendGeo);
              setConnections(prev => prev.map(c =>
                c.remoteAddr === geoIp ? { ...c, location: label, geoInfo: backendGeo } : c
              ));
              setDetections(prev => prev.map(d => {
                if (d.ip !== geoIp) return d;
                return { ...d, location: label, geoInfo: backendGeo, aiNote: localExplain(d.ip, d.port, d.protocol, label, d.reason) };
              }));
            }

            setConnections(prev => {
              // Extract the base connection to update or add
              const existingIdx = prev.findIndex(c => c.remoteAddr === data.remote_addr && c.remotePort === data.remote_port);
              
              const newConn: Connection = {
                id: existingIdx >= 0 ? prev[existingIdx].id : Math.random().toString(36).substr(2, 9),
                process: data.process || 'Active App',
                pid: data.pid || 0,
                remoteAddr: data.remote_addr,
                remotePort: data.remote_port,
                // If this event has traffic in one direction, update it. 
                // For the other direction, we keep the old value but decay it slightly 
                // to avoid flickering while still allowing it to reach 0 if traffic stops.
                download: data.direction === 'Inbound' 
                  ? (data.bytes / (1024 * 1024)) * 2 
                  : (existingIdx >= 0 ? prev[existingIdx].download * 0.5 : 0),
                upload: data.direction === 'Outbound' 
                  ? (data.bytes / (1024 * 1024)) * 2 
                  : (existingIdx >= 0 ? prev[existingIdx].upload * 0.5 : 0),
                status: data.threat_score >= 45 ? 'suspicious' : 'safe',
                protocol: data.protocol,
                location: locationLabel || (existingIdx >= 0 ? prev[existingIdx].location : ''),
                geoInfo: geoInfo || (existingIdx >= 0 ? prev[existingIdx].geoInfo : undefined),
                threatLabel: data.threat_label || 'Verified Stream'
              };

              if (existingIdx >= 0) {
                const updated = [...prev];
                // Replace with fresh snapshot for aggregated data (Smooth feel)
                updated[existingIdx] = {
                  ...newConn,
                };
                return updated;
              } else {
                return [newConn, ...prev].slice(0, 50);
              }
            });

            // Update Guardian Detections — deduplicated per IP+reason (60s cooldown), with GeoIP + auto-AI
            if (data.threat_score >= 45) {
              const dedupKey = `${data.remote_addr}:${data.threat_label}`;
              if (!detectionCooldownRef.current.has(dedupKey)) {
                detectionCooldownRef.current.add(dedupKey);
                setTimeout(() => detectionCooldownRef.current.delete(dedupKey), 60000);

                const detId = Math.random().toString(36).substr(2, 9);
                const detIp = data.remote_addr;
                const detLocation = locationLabel;

                setDetections(prev => [{
                  id: detId,
                  ip: detIp,
                  port: data.remote_port,
                  protocol: data.protocol,
                  reason: data.threat_label,
                  score: data.threat_score,
                  time: new Date().toLocaleTimeString(),
                  location: detLocation,
                  geoInfo: geoInfo,
                  aiNote: localExplain(detIp, data.remote_port, data.protocol, detLocation, data.threat_label),
                }, ...prev].slice(0, 50));

                const applyNote = (note: string) =>
                  setDetections(prev => prev.map(d => d.id === detId ? { ...d, aiNote: note } : d));

                if (useCloudAiRef.current) {
                  getAiClient()
                    .then(ai => ai.models.generateContent({
                      model: 'gemini-2.0-flash',
                      contents: `Analyze this network activity: IP ${detIp}:${data.remote_port} (${data.protocol}), process "${data.process || 'unknown'}". Detection reason: ${data.threat_label}. Location: ${detLocation}. In 1-2 sentences, identify what this IP likely belongs to and whether this traffic is likely benign or worth investigating.`
                    }))
                    .then(response => {
                      applyNote(response.text || 'Analysis complete.');
                    })
                    .catch(() => {
                      applyNote(localExplain(detIp, data.remote_port, data.protocol, detLocation, data.threat_label));
                    });
                } else {
                  // Cloud AI disabled or key missing — use local engine immediately
                  applyNote(localExplain(detIp, data.remote_port, data.protocol, detLocation, data.threat_label));
                }
              }
            }
          });
        }
      } catch (err) {
        console.error("Failed to initialize Tauri listener:", err);
      }
    }

    setupListener();

    return () => {
      if (unlisten) unlisten();
    };
  }, []);

  const stats = useMemo(() => ({
    activeConnections: connections.length,
    threatsBlocked: 24,
  }), [connections]);

  return (
    <div className="h-screen bg-[#0a0a0c] text-slate-300 font-sans selection:bg-emerald-500/30 overflow-hidden flex flex-col">
      {/* --- Header --- */}
      <header className="h-16 border-b border-white/5 bg-black/40 backdrop-blur-xl flex items-center justify-between px-6 shrink-0 z-50">
        <div className="flex items-center gap-4">
          <div className="w-10 h-10 bg-emerald-500/10 border border-emerald-500/20 rounded-xl flex items-center justify-center">
            <Shield className="w-6 h-6 text-emerald-500" />
          </div>
          <div>
            <h1 className="text-lg font-bold tracking-tight text-white leading-none">Vigilance</h1>
            <p className="text-[10px] text-slate-500 mt-1 uppercase tracking-widest font-mono">
              {isDesktop ? 'Guardian Core Active' : 'Simulation Mode'}
            </p>
          </div>
        </div>

        <div className="flex items-center gap-6">
          <div className="relative group">
            <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500 group-focus-within:text-emerald-500 transition-colors" />
            <input 
              type="text" 
              placeholder="Search address, process, status..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="bg-white/5 border border-white/5 rounded-full py-2 pl-9 pr-4 text-sm w-64 focus:outline-none focus:ring-2 focus:ring-emerald-500/20 focus:border-emerald-500/40 transition-all placeholder:text-slate-600"
            />
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={analyzeCurrentTab}
              disabled={aiTabAnalyzing}
              title="Ask AI to analyze this tab"
              className={cn(
                "flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs font-bold uppercase tracking-widest transition-all",
                aiTabAnalyzing
                  ? "border-purple-500/30 text-purple-400 bg-purple-500/5 animate-pulse cursor-not-allowed"
                  : "border-purple-500/30 text-purple-400 hover:bg-purple-500/10 hover:border-purple-500/50"
              )}
            >
              <Zap className="w-3.5 h-3.5" />
              {aiTabAnalyzing ? 'Analyzing…' : 'Ask AI'}
            </button>
            <button
              onClick={() => setActiveTab('notifications')}
              className={cn("p-2 rounded-lg transition-colors relative", activeTab === 'notifications' ? "text-emerald-500 bg-emerald-500/5" : "text-slate-400 hover:bg-white/5")}
            >
              <Bell className="w-5 h-5" />
              {detections.length > 0 && (
                <span className="absolute top-1 right-1 w-2 h-2 bg-red-500 rounded-full border-2 border-[#0a0a0c]" />
              )}
            </button>
            <button
              onClick={() => setActiveTab('settings')}
              className={cn("p-2 rounded-lg transition-colors", activeTab === 'settings' ? "text-emerald-500 bg-emerald-500/5" : "text-slate-400 hover:bg-white/5")}
            >
              <Settings className="w-5 h-5" />
            </button>
          </div>
        </div>
      </header>

      <div className="flex flex-1 overflow-hidden">
        {/* --- Sidebar --- */}
        <aside className="w-20 border-r border-white/5 flex flex-col items-center py-8 gap-6 shrink-0 bg-black/20">
          <SidebarItem 
            active={activeTab === 'live'} 
            onClick={() => setActiveTab('live')} 
            icon={<Activity className="w-6 h-6" />} 
            label="Live" 
          />
          <SidebarItem 
            active={activeTab === 'firewall'} 
            onClick={() => setActiveTab('firewall')} 
            icon={<ShieldOff className="w-6 h-6" />} 
            label="Walls" 
          />
          <SidebarItem 
            active={activeTab === 'guardian'} 
            onClick={() => setActiveTab('guardian')} 
            icon={<Cpu className="w-6 h-6" />} 
            label="Core" 
          />
          <SidebarItem 
            active={activeTab === 'notifications'} 
            onClick={() => setActiveTab('notifications')} 
            icon={<Bell className="w-6 h-6" />} 
            label="Alerts" 
          />
          <SidebarItem 
            active={activeTab === 'settings'} 
            onClick={() => setActiveTab('settings')} 
            icon={<Settings className="w-6 h-6" />} 
            label="System" 
          />
        </aside>

        {/* --- Main Dashboard --- */}
        <main className="flex-1 overflow-y-auto p-8 custom-scrollbar relative">
          {aiTabAnalysis && (
            <div className="mb-4 px-4 py-3 bg-purple-500/10 border border-purple-500/30 rounded-xl flex items-start gap-3">
              <Zap className="w-4 h-4 text-purple-400 mt-0.5 shrink-0" />
              <div className="flex-1 min-w-0">
                <p className="text-xs font-semibold text-purple-400 uppercase tracking-widest mb-1">AI Analysis</p>
                <p className="text-xs text-purple-300/80 leading-relaxed">{aiTabAnalysis}</p>
              </div>
              <button onClick={() => setAiTabAnalysis(null)} className="text-purple-400/50 hover:text-purple-400 text-xs shrink-0">✕</button>
            </div>
          )}
          {captureError && (
            <div className="mb-4 px-4 py-3 bg-red-500/10 border border-red-500/30 rounded-xl flex items-start gap-3">
              <AlertTriangle className="w-4 h-4 text-red-400 mt-0.5 shrink-0" />
              <div className="flex-1 min-w-0">
                <p className="text-xs font-semibold text-red-400">Capture Engine Error</p>
                <p className="text-xs text-red-400/70 mt-0.5">{captureError}</p>
              </div>
              <button onClick={() => setCaptureError(null)} className="text-red-400/50 hover:text-red-400 text-xs shrink-0">✕</button>
            </div>
          )}
          <AnimatePresence mode="wait">
            {activeTab === 'live' ? (
              <motion.div 
                key="live"
                initial={{ opacity: 0, scale: 0.98 }}
                animate={{ opacity: 1, scale: 1 }}
                exit={{ opacity: 0, scale: 0.98 }}
                className="max-w-7xl mx-auto space-y-8"
              >
            
            {/* Top Stat Cards */}
              <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
                <StatCard
                  label="Download"
                  value={formatDataSize(sessionTotalDown)}
                  icon={<ArrowDown className="text-emerald-500" />}
                  trend={formatRate(downRateMBps)}
                  trendLabel="Rate"
                  onClick={() => setSortKey('download')}
                  active={sortKey === 'download'}
                />
                <StatCard
                  label="Upload"
                  value={formatDataSize(sessionTotalUp)}
                  icon={<ArrowUp className="text-blue-500" />}
                  trend={formatRate(upRateMBps)}
                  trendLabel="Rate"
                  onClick={() => setSortKey('upload')}
                  active={sortKey === 'upload'}
                />
                <StatCard
                  label="Total Traffic"
                  value={formatDataSize(sessionTotalDown + sessionTotalUp)}
                  icon={<Zap className="text-pink-500" />}
                  trend={formatRate(downRateMBps + upRateMBps)}
                  trendLabel="Combined Rate"
                />
                <StatCard 
                  label="Active Streams" 
                  value={stats.activeConnections.toString()} 
                  icon={<Activity className="text-purple-500" />} 
                  onClick={() => setSortKey(null)}
                />
                <StatCard 
                  label="Guardian Blocked" 
                  value={stats.threatsBlocked.toString()} 
                  icon={<Shield className="text-amber-500" />} 
                  trend="Cloud Active"
                />
              </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* Main Graph */}
              <div className="lg:col-span-2 bg-black/40 border border-white/5 rounded-3xl p-6 backdrop-blur-md">
                <div className="flex items-center justify-between mb-8">
                  <div>
                    <h3 className="text-white font-semibold">Network Throughput</h3>
                    <p className="text-xs text-slate-500">Real-time bandwidth utilization</p>
                  </div>
                  <div className="flex gap-2">
                    <span className="flex items-center gap-1.5 text-[10px] font-medium uppercase tracking-wider bg-emerald-500/10 text-emerald-500 px-2 py-1 rounded-md">
                      <div className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" /> Live
                    </span>
                  </div>
                </div>
                <div className="h-64">
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={history}>
                      <defs>
                        <linearGradient id="colorDown" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#10b981" stopOpacity={0.1}/>
                          <stop offset="95%" stopColor="#10b981" stopOpacity={0}/>
                        </linearGradient>
                        <linearGradient id="colorUp" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.1}/>
                          <stop offset="95%" stopColor="#3b82f6" stopOpacity={0}/>
                        </linearGradient>
                      </defs>
                      <CartesianGrid strokeDasharray="3 3" stroke="#ffffff05" vertical={false} />
                      <XAxis dataKey="time" hide />
                      <YAxis hide />
                      <Tooltip
                        contentStyle={{ backgroundColor: '#111', border: '1px solid #333', borderRadius: '12px' }}
                        itemStyle={{ fontSize: '12px' }}
                        formatter={(value: unknown, name: unknown) => [`${Number(value ?? 0).toFixed(3)} MB/s`, name === 'down' ? 'Download' : 'Upload'] as [string, string]}
                        labelFormatter={(label: unknown) => String(label ?? '')}
                      />
                      <Area
                        type="natural"
                        dataKey="down"
                        stroke="#10b981"
                        fillOpacity={1}
                        fill="url(#colorDown)"
                        strokeWidth={2}
                        dot={false}
                        isAnimationActive={false}
                      />
                      <Area
                        type="natural"
                        dataKey="up"
                        stroke="#3b82f6"
                        fillOpacity={1}
                        fill="url(#colorUp)"
                        strokeWidth={2}
                        dot={false}
                        isAnimationActive={false}
                      />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              </div>

              {/* Side Status */}
              <div className="bg-black/40 border border-white/5 rounded-3xl p-6 backdrop-blur-md space-y-6">
                <div>
                  <h3 className="text-white font-semibold">Guardian Watch</h3>
                  <p className="text-xs text-slate-500">Security engine status & log</p>
                </div>

                <div className="space-y-4">
                  <div className="p-4 bg-white/5 border border-white/5 rounded-2xl flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <Zap className={cn("w-5 h-5", isGuardianActive ? "text-amber-500" : "text-slate-600")} />
                      <div>
                        <p className="text-sm font-medium text-white">Advanced Heuristics</p>
                        <p className="text-[10px] text-slate-500">Real-time binary analysis</p>
                      </div>
                    </div>
                    <button 
                      onClick={() => setIsGuardianActive(!isGuardianActive)}
                      className={cn(
                        "w-10 h-5 rounded-full relative transition-colors duration-200",
                        isGuardianActive ? "bg-emerald-500" : "bg-slate-700"
                      )}
                    >
                      <div className={cn(
                        "w-3.5 h-3.5 bg-white rounded-full absolute top-0.75 transition-all duration-200",
                        isGuardianActive ? "left-5.5" : "left-0.75"
                      )} />
                    </button>
                  </div>

                  <div className="space-y-3">
                     <p className="text-[10px] uppercase font-bold text-slate-600 tracking-widest pl-1">Recent Mitigations</p>
                     <MitigationLog 
                      app="svchost.exe" 
                      action="Filtered" 
                      desc="Blocked telemetry ping to MS metrics" 
                      time="2m ago"
                     />
                  </div>
                </div>
              </div>
            </div>

                 <div className="flex items-center justify-between mb-6">
                   <div className="flex gap-2">
                     <button 
                        onClick={() => setMonitoringMode('active')}
                        className={cn(
                          "px-4 py-2 rounded-xl text-[10px] uppercase tracking-widest font-bold transition-all border",
                          monitoringMode === 'active' ? "bg-emerald-500 text-black border-emerald-500" : "bg-white/5 text-slate-500 border-white/5 hover:bg-white/10"
                        )}
                     >
                       Active Mode
                     </button>
                     <button 
                        onClick={() => setMonitoringMode('audit')}
                        className={cn(
                          "px-4 py-2 rounded-xl text-[10px] uppercase tracking-widest font-bold transition-all border",
                          monitoringMode === 'audit' ? "bg-blue-500 text-white border-blue-500" : "bg-white/5 text-slate-500 border-white/5 hover:bg-white/10"
                        )}
                     >
                       Audit Mode
                     </button>
                   </div>
                   <div className="flex gap-4">
                     {monitoringMode === 'active' && (
                       <div className="px-4 py-2 bg-emerald-500/5 border border-emerald-500/20 rounded-xl flex items-center gap-2">
                          <div className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
                          <span className="text-[10px] uppercase font-bold text-emerald-500 tracking-wider">Live Capture Stream</span>
                       </div>
                     )}
                     {monitoringMode === 'audit' && (
                       <div className="px-4 py-2 bg-blue-500/5 border border-blue-500/20 rounded-xl flex items-center gap-2">
                          <Zap className="w-3 h-3 text-blue-500" />
                          <span className="text-[10px] uppercase font-bold text-blue-500 tracking-wider">Historical Traffic Audit</span>
                       </div>
                     )}
                   </div>
                 </div>

            {/* Main Table Section */}
            <div className="bg-black/40 border border-white/5 rounded-3xl overflow-hidden backdrop-blur-md">
              <div className="p-6 border-b border-white/5 flex items-center justify-between bg-white/[0.02]">
                <div className="flex items-center gap-3">
                  <Cpu className="w-5 h-5 text-emerald-500" />
                  <h3 className="text-white font-semibold">
                    {monitoringMode === 'audit' ? 'System Process Forensic Audit' : 'Process Activity Feed'}
                  </h3>
                </div>
                <div className="flex gap-2 relative">
                  <div className="flex gap-2">
                    <button 
                      onClick={() => setIsPaused(!isPaused)}
                      className={cn(
                        "flex items-center gap-2 px-3 py-1.5 rounded-lg border transition-all text-xs",
                        isPaused ? "bg-amber-500/10 border-amber-500 text-amber-500" : "border-white/5 text-slate-400 hover:bg-white/5"
                      )}
                    >
                      {isPaused ? <Zap className="w-3.5 h-3.5" /> : <Activity className="w-3.5 h-3.5" />} 
                      {isPaused ? 'Resume Feed' : 'Freeze Feed'}
                    </button>
                    <button 
                      onClick={() => setIsFilterOpen(!isFilterOpen)}
                      className={cn(
                        "flex items-center gap-2 px-3 py-1.5 rounded-lg border transition-all text-xs",
                        isFilterOpen ? "bg-emerald-500/10 border-emerald-500 text-emerald-500" : "border-white/5 text-slate-400 hover:bg-white/5"
                      )}
                    >
                      <Filter className="w-3.5 h-3.5" /> Filter
                    </button>
                    {isFilterOpen && (
                      <div className="absolute top-full right-0 mt-2 w-48 bg-[#1a1a1e] border border-white/10 rounded-xl p-2 shadow-2xl z-[100] animate-in fade-in slide-in-from-top-2">
                        {(['all', 'safe', 'suspicious', 'blocked'] as const).map((type) => (
                          <button
                            key={type}
                            onClick={() => {
                              setFilterType(type);
                              setIsFilterOpen(false);
                            }}
                            className={cn(
                              "w-full text-left px-3 py-2 rounded-lg text-[10px] uppercase tracking-widest font-bold transition-colors",
                              filterType === type ? "bg-emerald-500/20 text-emerald-500" : "text-slate-500 hover:bg-white/5"
                            )}
                          >
                            {type} Connections
                          </button>
                        ))}
                      </div>
                    )}
                    <button 
                      onClick={exportToCsv}
                      className="flex items-center gap-2 px-3 py-1.5 rounded-lg border border-white/5 hover:bg-white/5 transition-colors text-xs text-slate-400"
                    >
                      <Download className="w-3.5 h-3.5" /> Export CSV
                    </button>
                  </div>
                </div>
              </div>

              <div>
                <table className="w-full text-left border-collapse table-fixed">
                  <colgroup>
                    <col className="w-20" />
                    <col className="w-[24%]" />
                    <col className="w-[24%]" />
                    <col className="w-[18%]" />
                    <col className="w-[20%]" />
                    <col className="w-16" />
                  </colgroup>
                  <thead>
                    <tr className="border-b border-white/5 text-[10px] uppercase tracking-widest font-bold text-slate-500">
                      <th className="px-4 py-4">Status</th>
                      <th className="px-4 py-4 cursor-pointer select-none hover:text-slate-300 transition-colors" onClick={() => handleGroupSort('process')}>
                        Process / PID <SortArrow col="process" />
                      </th>
                      <th className="px-4 py-4 cursor-pointer select-none hover:text-slate-300 transition-colors" onClick={() => handleGroupSort('endpoints')}>
                        Endpoint <SortArrow col="endpoints" />
                      </th>
                      <th className="px-4 py-4">Protocol / Port</th>
                      <th className="px-4 py-4 text-right cursor-pointer select-none hover:text-slate-300 transition-colors" onClick={() => handleGroupSort('dataRate')}>
                        Data Rate <SortArrow col="dataRate" />
                      </th>
                      <th className="px-4 py-4 cursor-pointer select-none hover:text-slate-300 transition-colors text-center" onClick={() => handleGroupSort('pid')}>
                        PID <SortArrow col="pid" />
                      </th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-white/[0.03]">
                    <AnimatePresence mode="popLayout">
                      {monitoringMode === 'audit'
                        ? groupedConnections.map((group) => (
                          <React.Fragment key={group.process}>
                            <motion.tr
                              layout
                              onClick={() => {
                                const next = new Set(expandedProcesses);
                                if (next.has(group.process)) next.delete(group.process);
                                else next.add(group.process);
                                setExpandedProcesses(next);
                              }}
                              className="group hover:bg-white/[0.02] transition-colors cursor-pointer"
                            >
                              <td className="px-6 py-4 whitespace-nowrap">
                                <div className={cn(
                                  "w-2 h-2 rounded-full",
                                  group.status === 'safe' ? "bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.5)]" : 
                                  "bg-amber-500 shadow-[0_0_8px_rgba(245,158,11,0.5)]"
                                )} />
                              </td>
                              <td className="px-6 py-4 whitespace-nowrap">
                                <div className="flex flex-col">
                                  <span className="text-sm font-bold text-white flex items-center gap-2">
                                    {group.process}
                                    <span className="text-[10px] bg-white/5 px-1.5 py-0.5 rounded text-slate-500 font-normal">
                                      {group.connections.length} Endpoints
                                    </span>
                                  </span>
                                  <span className="text-[10px] font-mono text-slate-500 font-normal uppercase tracking-widest mt-0.5">Application Aggregate</span>
                                </div>
                              </td>
                              <td className="px-6 py-4">
                                <span className="text-xs text-slate-500 italic">Aggregated forensics via {group.connections.length} targets</span>
                              </td>
                              <td className="px-6 py-4 whitespace-nowrap">
                                <span className="text-[10px] font-bold text-slate-600 uppercase tracking-widest">Multi-Socket Container</span>
                              </td>
                              <td className="px-6 py-4 whitespace-nowrap text-right">
                                <div className="flex flex-col items-end gap-0.5">
                                  <div className="flex items-center gap-1.5">
                                    <ArrowDown className="w-3 h-3 text-emerald-500" />
                                    <span className="text-xs font-mono text-emerald-500">{formatRate(group.totalDownload)}</span>
                                  </div>
                                  <span className="text-[10px] font-mono text-slate-500">{formatDataSize(group.totalDownBytes)} total ↓</span>
                                  <div className="flex items-center gap-1.5 mt-0.5">
                                    <ArrowUp className="w-3 h-3 text-blue-500" />
                                    <span className="text-xs font-mono text-blue-500">{formatRate(group.totalUpload)}</span>
                                  </div>
                                  <span className="text-[10px] font-mono text-slate-500">{formatDataSize(group.totalUpBytes)} total ↑</span>
                                </div>
                              </td>
                              <td className="px-6 py-4 whitespace-nowrap text-right">
                                <MoreVertical className={cn("w-4 h-4 text-slate-600 transition-transform", expandedProcesses.has(group.process) ? "rotate-90 text-white" : "")} />
                              </td>
                            </motion.tr>
                            {expandedProcesses.has(group.process) && group.connections.map((conn) => (
                              <motion.tr
                                key={conn.id}
                                initial={{ opacity: 0, height: 0 }}
                                animate={{ opacity: 1, height: 'auto' }}
                                className="bg-white/[0.01] border-l-2 border-emerald-500/20"
                              >
                                <td className="px-6 py-2"></td>
                                <td className="px-6 py-2">
                                  <span className="text-xs text-slate-400 font-mono">Sub-socket {conn.id}</span>
                                </td>
                                <td className="px-6 py-2">
                                  <span className="text-xs text-slate-500 font-mono">{conn.remoteAddr}</span>
                                </td>
                                <td className="px-6 py-2">
                                  <span className="text-xs text-slate-600 font-mono">Port {conn.remotePort}</span>
                                </td>
                                <td className="px-6 py-2 text-right">
                                  <span className="text-[10px] text-slate-600 font-mono flex items-center justify-end gap-1">
                                    <ArrowDown className="w-2.5 h-2.5" /> {formatRate(conn.download)}
                                  </span>
                                  <span className="text-[10px] text-slate-600 font-mono flex items-center justify-end gap-1">
                                    <ArrowUp className="w-2.5 h-2.5" /> {formatRate(conn.upload)}
                                  </span>
                                </td>
                                <td className="px-6 py-2"></td>
                              </motion.tr>
                            ))}
                          </React.Fragment>
                        ))
                        : groupedConnections.map((group) => (
                          <React.Fragment key={group.process}>
                            <motion.tr
                              layout
                              onClick={() => {
                                const next = new Set(expandedProcesses);
                                if (next.has(group.process)) next.delete(group.process);
                                else next.add(group.process);
                                setExpandedProcesses(next);
                              }}
                              className="group hover:bg-white/[0.02] transition-colors cursor-pointer"
                            >
                              <td className="px-4 py-4">
                                <div className={cn(
                                  "w-2 h-2 rounded-full",
                                  group.status === 'safe' ? "bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.5)]" :
                                  group.status === 'suspicious' ? "bg-amber-500 shadow-[0_0_8px_rgba(245,158,11,0.5)]" :
                                  "bg-red-500 shadow-[0_0_8px_rgba(239,68,68,0.5)]"
                                )} />
                              </td>
                              <td className="px-4 py-4 overflow-hidden">
                                <div className="flex flex-col min-w-0">
                                  <span className={cn(
                                    "text-sm font-bold flex items-center gap-2 min-w-0",
                                    group.status === 'safe' ? "text-white" : "text-amber-500"
                                  )}>
                                    <span className="truncate">{group.process}</span>
                                    <span className="text-[10px] bg-white/5 px-1.5 py-0.5 rounded text-slate-500 font-normal shrink-0">
                                      {group.connections.length} {group.connections.length === 1 ? 'Conn' : 'Conns'}
                                    </span>
                                  </span>
                                  <span className="text-[10px] font-mono text-slate-500">PID: {group.pid}</span>
                                </div>
                              </td>
                              <td className="px-4 py-4 overflow-hidden">
                                <div className="flex flex-col gap-0.5 min-w-0">
                                  {group.connections.slice(0, 2).map(c => (
                                    <div key={c.id} className="flex items-center gap-1.5 min-w-0">
                                      <span className="text-xs text-slate-500 font-mono truncate">{c.remoteAddr}</span>
                                      {shortGeo(c.location) && (
                                        <span className="text-[9px] text-slate-600 flex items-center gap-0.5 shrink-0">
                                          <Globe className="w-2.5 h-2.5" />{shortGeo(c.location)}
                                        </span>
                                      )}
                                    </div>
                                  ))}
                                  {group.connections.length > 2 && (
                                    <span className="text-[10px] text-slate-600">+{group.connections.length - 2} more</span>
                                  )}
                                </div>
                              </td>
                              <td className="px-4 py-4">
                                <div className="flex flex-wrap gap-1">
                                  {[...new Set(group.connections.map(c => c.protocol))].map(p => (
                                    <span key={p} className="text-[9px] font-bold px-1.5 py-0.5 rounded bg-white/5 border border-white/5 text-slate-500 uppercase tracking-wider whitespace-nowrap">{p}</span>
                                  ))}
                                </div>
                              </td>
                              <td className="px-4 py-4 text-right">
                                <div className="flex flex-col items-end gap-0.5">
                                  <div className="flex items-center gap-1.5">
                                    <ArrowDown className="w-3 h-3 text-emerald-500" />
                                    <span className="text-sm font-mono text-emerald-500">{formatRate(group.totalDownload)}</span>
                                  </div>
                                  <span className="text-[10px] font-mono text-slate-500">{formatDataSize(group.totalDownBytes)} ↓</span>
                                  <div className="flex items-center gap-1.5 mt-0.5">
                                    <ArrowUp className="w-3 h-3 text-blue-500" />
                                    <span className="text-sm font-mono text-blue-500">{formatRate(group.totalUpload)}</span>
                                  </div>
                                  <span className="text-[10px] font-mono text-slate-500">{formatDataSize(group.totalUpBytes)} ↑</span>
                                </div>
                              </td>
                              <td className="px-4 py-4 text-right">
                                <MoreVertical className={cn("w-4 h-4 text-slate-600 transition-transform", expandedProcesses.has(group.process) ? "rotate-90 text-white" : "")} />
                              </td>
                            </motion.tr>
                            {expandedProcesses.has(group.process) && group.connections.map((conn) => (
                              <motion.tr
                                key={conn.id}
                                initial={{ opacity: 0, height: 0 }}
                                animate={{ opacity: 1, height: 'auto' }}
                                className="bg-white/[0.01] border-l-2 border-emerald-500/20 group/sub"
                              >
                                <td className="px-4 py-2">
                                  <div className={cn(
                                    "w-1.5 h-1.5 rounded-full ml-0.5",
                                    conn.status === 'safe' ? "bg-emerald-500/60" :
                                    conn.status === 'suspicious' ? "bg-amber-500/60" :
                                    "bg-red-500/60"
                                  )} />
                                </td>
                                <td className="px-4 py-2 overflow-hidden">
                                  <div className="flex flex-col min-w-0">
                                    <span className="text-[10px] font-mono text-slate-400">Socket {conn.id}</span>
                                    {aiAnalysis[conn.id] && (
                                      <span className="text-[10px] text-emerald-500/80 italic border-l border-emerald-500/50 pl-2 mt-0.5 line-clamp-2" title={aiAnalysis[conn.id]}>
                                        AI: {aiAnalysis[conn.id]}
                                      </span>
                                    )}
                                  </div>
                                </td>
                                <td className="px-4 py-2 overflow-hidden">
                                  <div className="flex flex-col min-w-0">
                                    <span className="text-xs text-slate-300 font-mono truncate">{conn.remoteAddr}</span>
                                    {conn.geoInfo && (
                                      <div className="flex flex-col gap-0.5">
                                        <span className="text-[9px] text-slate-500 flex items-center gap-1 truncate" title={conn.location}>
                                          <Globe className="w-2.5 h-2.5 shrink-0" /> {conn.geoInfo.country_code} — {conn.geoInfo.city}, {conn.geoInfo.region}
                                        </span>
                                        <span className="text-[9px] text-emerald-500/70 font-bold uppercase tracking-widest truncate">
                                          {conn.geoInfo.asn} {conn.geoInfo.org}
                                        </span>
                                      </div>
                                    )}
                                    <span className={cn(
                                      "text-[9px] font-bold uppercase tracking-wider flex items-center gap-1 truncate",
                                      conn.threatLabel.includes('HIGH RISK') ? "text-red-500 animate-pulse" :
                                      conn.threatLabel.includes('Suspicious') ? "text-amber-500" : "text-slate-500"
                                    )} title={conn.threatLabel}>
                                      <Shield className="w-2.5 h-2.5 shrink-0" /> {conn.threatLabel}
                                    </span>
                                  </div>
                                </td>
                                <td className="px-4 py-2 overflow-hidden">
                                  <div className="flex flex-col gap-0.5 min-w-0">
                                    <span className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-white/5 border border-white/5 text-slate-400 self-start">{conn.protocol}</span>
                                    {PROTOCOL_DESC[conn.protocol] ? (
                                      <span className="text-[9px] text-slate-600 italic truncate">{PROTOCOL_DESC[conn.protocol]}</span>
                                    ) : conn.protocol.startsWith('PROTO-') ? (
                                      <span className="text-[9px] text-slate-600 italic">proto {conn.protocol.slice(6)}</span>
                                    ) : conn.remotePort > 0 ? (
                                      <span className="text-xs text-slate-400 font-mono">:{conn.remotePort}</span>
                                    ) : null}
                                  </div>
                                </td>
                                <td className="px-4 py-2 text-right">
                                  <div className="flex flex-col items-end">
                                    <span className="text-xs font-mono text-emerald-500/70 flex items-center gap-1">
                                      <ArrowDown className="w-2.5 h-2.5" /> {formatRate(conn.download)}
                                    </span>
                                    <span className="text-xs font-mono text-blue-500/70 flex items-center gap-1">
                                      <ArrowUp className="w-2.5 h-2.5" /> {formatRate(conn.upload)}
                                    </span>
                                  </div>
                                </td>
                                <td className="px-4 py-2 text-right">
                                  <button
                                    onClick={(e) => { e.stopPropagation(); analyzeThreat(conn); }}
                                    className="p-1.5 hover:bg-white/10 rounded-md transition-colors opacity-0 group-hover/sub:opacity-100 text-amber-500"
                                    title="Analyze with AI"
                                  >
                                    <Zap className="w-3.5 h-3.5" />
                                  </button>
                                  <button
                                    onClick={(e) => { e.stopPropagation(); blockConnection(conn.remoteAddr); }}
                                    className="p-1.5 hover:bg-white/10 rounded-md transition-colors opacity-0 group-hover/sub:opacity-100 text-red-500"
                                    title="Block in Firewall"
                                  >
                                    <Lock className="w-3.5 h-3.5" />
                                  </button>
                                </td>
                              </motion.tr>
                            ))}
                          </React.Fragment>
                        ))}
                    </AnimatePresence>
                  </tbody>
                </table>
              </div>
            </div>

              </motion.div>
            ) : activeTab === 'notifications' ? (
              <motion.div 
                key="notifications"
                initial={{ opacity: 0, scale: 0.98 }}
                animate={{ opacity: 1, scale: 1 }}
                exit={{ opacity: 0, scale: 0.98 }}
                className="max-w-4xl mx-auto space-y-8"
              >
                <div className="bg-black/40 border border-white/5 rounded-3xl p-8 backdrop-blur-md">
                   <div className="flex items-center justify-between mb-8">
                     <div className="flex items-center gap-4">
                       <div className="p-3 bg-amber-500/10 rounded-2xl">
                         <Bell className="w-6 h-6 text-amber-500" />
                       </div>
                       <div>
                         <h2 className="text-2xl font-bold text-white">Security Notifications</h2>
                         <p className="text-sm text-slate-500">Live feed of heuristic detections and blocked attempts</p>
                       </div>
                     </div>
                     <div className="flex gap-2">
                       <button
                         onClick={() => exportDetectionsCsv('vigilance_alerts_log')}
                         disabled={detections.length === 0}
                         className="px-4 py-2 bg-white/5 hover:bg-white/10 rounded-xl border border-white/10 transition-colors text-xs font-bold text-slate-400 uppercase tracking-widest flex items-center gap-2 disabled:opacity-30 disabled:cursor-not-allowed"
                       >
                         <Download className="w-3.5 h-3.5" /> Export Log
                       </button>
                       <button
                         onClick={() => setDetections([])}
                         className="px-4 py-2 bg-white/5 hover:bg-white/10 rounded-xl border border-white/10 transition-colors text-xs font-bold text-slate-400 uppercase tracking-widest"
                       >
                         Clear History
                       </button>
                     </div>
                   </div>

                   <div className="space-y-4">
                     {detections.map((det) => (
                       <div key={det.id} className="p-5 bg-white/[0.02] border border-white/5 rounded-2xl flex items-start justify-between group hover:border-amber-500/20 transition-all">
                          <div className="flex items-start gap-5 flex-1 min-w-0">
                            <div className="w-10 h-10 rounded-xl bg-amber-500/10 flex items-center justify-center text-amber-500 shrink-0 mt-0.5">
                              <Shield className="w-5 h-5" />
                            </div>
                            <div className="flex-1 min-w-0">
                              <div className="flex items-center gap-2 flex-wrap">
                                <span className="text-sm font-bold text-white uppercase tracking-tight">{det.reason}</span>
                                <span className="text-[10px] px-2 py-0.5 rounded-full bg-red-500/20 text-red-500 font-mono">
                                  Score: {det.score}
                                </span>
                              </div>
                              <div className="flex items-center gap-3 mt-1 flex-wrap">
                                <span className="text-xs text-slate-500">
                                  From <span className="font-mono text-slate-300">{det.ip}</span>
                                  {det.port > 0 && <span className="font-mono text-slate-600">:{det.port}</span>}
                                </span>
                                {det.geoInfo && (
                                  <span className="text-[10px] text-slate-400 flex items-center gap-1 bg-white/5 px-2 py-0.5 rounded-lg">
                                    <Globe className="w-3 h-3 shrink-0" /> {det.geoInfo.country_code} · {det.geoInfo.asn} · {det.geoInfo.org}
                                  </span>
                                )}
                              </div>
                              {det.aiNote ? (
                                <p className="text-[11px] text-emerald-400/80 italic mt-2 border-l-2 border-emerald-500/30 pl-2">{det.aiNote}</p>
                              ) : useCloudAi && (
                                <p className="text-[10px] text-slate-600 italic mt-1 animate-pulse">AI analyzing connection...</p>
                              )}
                            </div>
                          </div>
                          <div className="flex flex-col items-end gap-2 shrink-0 ml-4">
                             <p className="text-xs font-mono text-slate-400">{det.time}</p>
                             <button
                               onClick={() => analyzeDetection(det)}
                               disabled={analyzingDetections.has(det.id)}
                               className={cn(
                                 "px-3 py-1.5 rounded-lg text-[10px] font-bold uppercase tracking-widest transition-all flex items-center gap-1",
                                 analyzingDetections.has(det.id)
                                   ? "bg-purple-500/5 text-purple-400/50 cursor-not-allowed"
                                   : "bg-purple-500/10 hover:bg-purple-500/20 text-purple-400"
                               )}
                             >
                               <Zap className="w-3 h-3" />
                               {analyzingDetections.has(det.id) ? 'Asking…' : 'Ask AI'}
                             </button>
                             <p className="text-[10px] text-slate-600 uppercase tracking-widest">Kernel Blocked</p>
                          </div>
                       </div>
                     ))}
                     {detections.length === 0 && (
                       <div className="py-20 flex flex-col items-center gap-4 text-slate-600 grayscale">
                         <Bell className="w-12 h-12 opacity-10" />
                         <p className="text-sm font-medium">System is clean. No high-risk detections.</p>
                       </div>
                     )}
                   </div>
                </div>
              </motion.div>
            ) : activeTab === 'settings' ? (
              <motion.div 
                key="settings"
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: 10 }}
                className="max-w-2xl mx-auto"
              >
                <div className="bg-black/40 border border-white/5 rounded-3xl p-8 backdrop-blur-md">
                   <div className="flex items-center gap-4 mb-8">
                     <div className="p-3 bg-emerald-500/10 rounded-2xl">
                       <Settings className="w-6 h-6 text-emerald-500" />
                     </div>
                     <div>
                       <h2 className="text-2xl font-bold text-white">System Settings</h2>
                       <p className="text-sm text-slate-500">Configure your Guardian core preferences</p>
                     </div>
                   </div>

                   <div className="space-y-6">
                     <div className="p-6 bg-white/[0.02] border border-white/5 rounded-2xl flex items-center justify-between group hover:border-white/10 transition-colors">
                       <div className="flex items-center gap-4">
                         <div className="p-2 bg-blue-500/10 rounded-lg">
                           <Zap className="w-5 h-5 text-blue-500" />
                         </div>
                         <div>
                           <p className="text-sm font-semibold text-white">Advanced AI Guardian</p>
                           <p className="text-xs text-slate-500">Cloud-based threat analysis via Gemini 3 Flash</p>
                           <p className="text-xs text-slate-600 mt-0.5">{aiRequestCount} request{aiRequestCount !== 1 ? 's' : ''} this session</p>
                         </div>
                       </div>
                       <button 
                         onClick={() => setUseCloudAi(!useCloudAi)}
                         className={cn(
                           "w-11 h-6 rounded-full transition-all relative flex items-center px-1",
                           useCloudAi ? "bg-emerald-500 shadow-[0_0_10px_rgba(16,185,129,0.2)]" : "bg-slate-700"
                         )}
                       >
                         <motion.div 
                           animate={{ x: useCloudAi ? 20 : 0 }}
                           className="w-4 h-4 bg-white rounded-full shadow-sm" 
                         />
                       </button>
                     </div>

                     {aiQuotaError && (
                       <div className="px-4 py-3 bg-red-500/10 border border-red-500/20 rounded-xl flex items-start gap-3">
                         <AlertTriangle className="w-4 h-4 text-red-400 mt-0.5 shrink-0" />
                         <div>
                           <p className="text-xs font-semibold text-red-400">AI Quota Alert</p>
                           <p className="text-xs text-red-400/70 mt-0.5">{aiQuotaError}</p>
                         </div>
                         <button onClick={() => setAiQuotaError(null)} className="ml-auto text-red-400/50 hover:text-red-400 text-xs">✕</button>
                       </div>
                     )}

                     <div className="p-6 bg-white/[0.02] border border-white/5 rounded-2xl flex items-center justify-between group hover:border-white/10 transition-colors">
                       <div className="flex items-center gap-4">
                         <div className="p-2 bg-purple-500/10 rounded-lg">
                           <Bell className="w-5 h-5 text-purple-500" />
                         </div>
                         <div>
                           <p className="text-sm font-semibold text-white">System Notifications</p>
                           <p className="text-xs text-slate-500">Enable real-time desktop alerts for blocked threats</p>
                         </div>
                       </div>
                       <button 
                         onClick={() => setNotificationsEnabled(!notificationsEnabled)}
                         className={cn(
                           "w-11 h-6 rounded-full transition-all relative flex items-center px-1",
                           notificationsEnabled ? "bg-emerald-500 shadow-[0_0_10px_rgba(16,185,129,0.2)]" : "bg-slate-700"
                         )}
                       >
                         <motion.div 
                           animate={{ x: notificationsEnabled ? 20 : 0 }}
                           className="w-4 h-4 bg-white rounded-full shadow-sm" 
                         />
                       </button>
                     </div>

                     <div className="p-6 bg-white/[0.02] border border-white/5 rounded-2xl space-y-4">
                       <div className="flex items-center gap-4">
                         <div className="p-2 bg-emerald-500/10 rounded-lg">
                           <Cpu className="w-5 h-5 text-emerald-500" />
                         </div>
                         <div>
                           <p className="text-sm font-semibold text-white">Capture Interface</p>
                           <p className="text-xs text-slate-500">Select the network adapter for Guardian to monitor</p>
                         </div>
                       </div>
                       <select 
                         value={selectedInterface}
                         onChange={(e) => setSelectedInterface(e.target.value)}
                         className="w-full bg-black/40 border border-white/10 rounded-xl px-4 py-2 text-sm text-slate-300 focus:outline-none focus:ring-2 focus:ring-emerald-500/20"
                       >
                         {availableInterfaces.map(iface => (
                           <option key={iface.name} value={iface.name}>
                             {iface.description || iface.name}
                           </option>
                         ))}
                         {availableInterfaces.length === 0 && <option>No Interfaces Detected</option>}
                       </select>
                     </div>
                   </div>
                </div>
              </motion.div>
            ) : activeTab === 'firewall' ? (
              <motion.div 
                key="firewall"
                initial={{ opacity: 0, scale: 0.98 }}
                animate={{ opacity: 1, scale: 1 }}
                exit={{ opacity: 0, scale: 0.98 }}
                className="max-w-4xl mx-auto space-y-8"
              >
                <div className="bg-black/40 border border-white/5 rounded-3xl p-8 backdrop-blur-md">
                   <div className="flex items-center justify-between mb-8">
                     <div className="flex items-center gap-4">
                       <div className="p-3 bg-red-500/10 rounded-2xl">
                         <ShieldOff className="w-6 h-6 text-red-500" />
                       </div>
                       <div>
                         <h2 className="text-2xl font-bold text-white">System Firewall (Walls)</h2>
                         <p className="text-sm text-slate-500">Managing global packet filters and blocked address ranges</p>
                       </div>
                     </div>
                     <button 
                       onClick={async () => {
                         const rules = await invoke<string[]>('get_firewall_rules');
                         setFirewallRules(rules);
                       }}
                       className="px-4 py-2 bg-white/5 hover:bg-white/10 rounded-xl border border-white/10 transition-colors text-xs font-bold text-white uppercase tracking-widest"
                     >
                       Refresh List
                     </button>
                   </div>

                   <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                     {firewallRules.map((ruleIp) => (
                       <div key={ruleIp} className="p-4 bg-white/[0.02] border border-white/5 rounded-2xl flex items-center justify-between group hover:border-red-500/30 transition-all">
                         <div className="flex items-center gap-3">
                           <div className="w-2 h-2 rounded-full bg-red-500 shadow-[0_0_10px_rgba(239,68,68,0.5)]" />
                           <span className="text-sm font-mono text-slate-300">{ruleIp}</span>
                         </div>
                         <button 
                           onClick={() => deleteRule(ruleIp)}
                           className="p-2 opacity-0 group-hover:opacity-100 hover:bg-red-500/20 rounded-lg text-red-500 transition-all"
                         >
                           <Trash2 className="w-4 h-4" />
                         </button>
                       </div>
                     ))}
                     {firewallRules.length === 0 && (
                       <div className="col-span-full py-12 flex flex-col items-center gap-3 text-slate-600 border border-white/5 border-dashed rounded-3xl">
                         <Lock className="w-8 h-8 opacity-20" />
                         <p className="text-sm">No active Vanguard blocking rules found.</p>
                       </div>
                     )}
                   </div>
                </div>
              </motion.div>
            ) : activeTab === 'guardian' ? (
              <motion.div 
                key="guardian"
                initial={{ opacity: 0, scale: 0.98 }}
                animate={{ opacity: 1, scale: 1 }}
                exit={{ opacity: 0, scale: 0.98 }}
                className="max-w-4xl mx-auto space-y-8"
              >
                <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                  <div className="bg-emerald-500/10 border border-emerald-500/20 rounded-3xl p-6 flex flex-col gap-2">
                    <span className="text-[10px] uppercase tracking-widest font-bold text-emerald-500/60">Risk Threshold</span>
                    <span className="text-3xl font-bold text-emerald-500">45.0%</span>
                  </div>
                  <div className="bg-amber-500/10 border border-amber-500/20 rounded-3xl p-6 flex items-center justify-between group">
                    <div>
                      <span className="text-[10px] uppercase tracking-widest font-bold text-amber-500/60">Heuristic Engine</span>
                      <div className="flex items-center gap-2">
                        <div className="w-2 h-2 rounded-full bg-amber-500 animate-pulse" />
                        <span className="text-lg font-bold text-amber-500">v1.0 Trace Engine</span>
                      </div>
                    </div>
                    <button 
                      onClick={async () => {
                        const next = !isGuardianActive;
                        setIsGuardianActive(next);
                        if (isDesktop) {
                          await invoke('toggle_heuristics', { enabled: next });
                        }
                      }}
                      className={cn(
                        "w-11 h-6 rounded-full transition-all relative flex items-center px-1",
                        isGuardianActive ? "bg-emerald-500 shadow-[0_0_10px_rgba(16,185,129,0.2)]" : "bg-slate-700"
                      )}
                    >
                      <motion.div 
                        animate={{ x: isGuardianActive ? 20 : 0 }}
                        className="w-4 h-4 bg-white rounded-full shadow-sm" 
                      />
                    </button>
                  </div>
                  <div className="bg-blue-500/10 border border-blue-500/20 rounded-3xl p-6 flex flex-col gap-2">
                    <span className="text-[10px] uppercase tracking-widest font-bold text-blue-500/60">Identity Shield</span>
                    <span className="text-lg font-bold text-blue-500">Kernel Active</span>
                  </div>
                </div>

                <div className="bg-black/40 border border-white/5 rounded-3xl p-8 backdrop-blur-md">
                   <div className="flex items-center justify-between mb-8">
                     <div className="flex items-center gap-4">
                       <div className="p-3 bg-blue-500/10 rounded-2xl">
                         <Zap className="w-6 h-6 text-blue-500" />
                       </div>
                       <div>
                         <h2 className="text-2xl font-bold text-white">Heuristic Event Log</h2>
                         <p className="text-sm text-slate-500">Real-time behavioral anomalies identified by the v1.0 engine</p>
                       </div>
                     </div>
                     <button
                       onClick={() => exportDetectionsCsv('vigilance_heuristic_log')}
                       disabled={detections.length === 0}
                       className="px-4 py-2 bg-white/5 hover:bg-white/10 rounded-xl border border-white/10 transition-colors text-xs font-bold text-slate-400 uppercase tracking-widest flex items-center gap-2 disabled:opacity-30 disabled:cursor-not-allowed"
                     >
                       <Download className="w-3.5 h-3.5" /> Export Log
                     </button>
                   </div>

                   <div className="space-y-3">
                     {detections.map((det) => (
                       <div key={det.id} className="p-5 bg-white/[0.02] border border-white/5 rounded-2xl flex items-start justify-between group hover:border-white/20 transition-all">
                         <div className="flex flex-col gap-1 flex-1 min-w-0 mr-4">
                           <div className="flex items-center gap-3 flex-wrap">
                             <span className="text-sm font-mono text-white">{det.ip}</span>
                             {det.port > 0 && <span className="text-slate-600 font-mono text-xs">:{det.port}</span>}
                             <span className="px-2 py-0.5 rounded-md bg-red-500/20 text-red-500 text-[10px] font-bold uppercase tracking-wider">
                               Score: {det.score}
                             </span>
                           </div>
                           {det.location && (
                             <span className="text-[10px] text-slate-400 flex items-center gap-1">
                               <Globe className="w-3 h-3 shrink-0" /> {det.location}
                             </span>
                           )}
                           <p className="text-xs text-slate-500 leading-relaxed">{det.reason}</p>
                           {det.aiNote ? (
                             <p className="text-[11px] text-emerald-400/80 italic mt-1 border-l-2 border-emerald-500/30 pl-2">{det.aiNote}</p>
                           ) : useCloudAi && (
                             <p className="text-[10px] text-slate-600 italic animate-pulse">AI analyzing connection...</p>
                           )}
                         </div>
                         <div className="flex flex-col items-end gap-2 shrink-0">
                           <p className="text-[10px] font-mono text-slate-600">{det.time}</p>
                           <button
                             onClick={() => analyzeDetection(det)}
                             disabled={analyzingDetections.has(det.id)}
                             className={cn(
                               "px-3 py-1.5 rounded-lg text-[10px] font-bold uppercase tracking-widest transition-all flex items-center gap-1",
                               analyzingDetections.has(det.id)
                                 ? "bg-purple-500/5 text-purple-400/50 cursor-not-allowed"
                                 : "bg-purple-500/10 hover:bg-purple-500/20 text-purple-400"
                             )}
                           >
                             <Zap className="w-3 h-3" />
                             {analyzingDetections.has(det.id) ? 'Asking…' : 'Ask AI'}
                           </button>
                           <button
                             onClick={() => blockConnection(det.ip)}
                             className="px-3 py-1.5 bg-red-500/10 hover:bg-red-500/20 text-red-500 rounded-lg text-[10px] font-bold uppercase tracking-widest transition-all"
                           >
                             Block IP
                           </button>
                         </div>
                       </div>
                     ))}
                     {detections.length === 0 && (
                       <div className="py-20 flex flex-col items-center gap-3 text-slate-600 border border-white/5 border-dashed rounded-3xl">
                         <Shield className="w-8 h-8 opacity-20" />
                         <p className="text-sm">No suspicious behaviors detected in current session.</p>
                       </div>
                     )}
                   </div>
                </div>
              </motion.div>
            ) : (
                <motion.div 
                  key="other"
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  className="flex flex-col items-center justify-center min-h-[50vh] text-center"
                >
                  <Shield className="w-16 h-16 text-slate-700 mb-4" />
                  <h3 className="text-lg font-bold text-white">Advanced Module</h3>
                  <p className="text-sm text-slate-500 max-w-xs mx-auto">This section is currently under specialized security review for the 1.0 release.</p>
                </motion.div>
            )}
          </AnimatePresence>
        </main>
      </div>

      {/* --- Overlay UI Elements --- */}
      <div className="fixed bottom-6 right-6 flex flex-col gap-3 pointer-events-none">
        <div className="bg-emerald-500/10 border border-emerald-500/20 backdrop-blur-xl px-4 py-2 rounded-2xl flex items-center gap-3 shadow-2xl pointer-events-auto transition-transform hover:scale-105">
           <div className="w-2 h-2 rounded-full bg-emerald-500 animate-ping" />
           <span className="text-[10px] font-bold text-emerald-500 uppercase tracking-widest whitespace-nowrap">
             Kernel Shield v2.4 Active
           </span>
        </div>
      </div>
    </div>
  );
}

const PROTOCOL_DESC: Record<string, string> = {
  ICMP:   'ping / traceroute',
  ICMPv6: 'ping / traceroute (IPv6)',
  IGMP:   'multicast group',
  IPIP:   'IP-in-IP tunnel',
  GRE:    'VPN tunnel (GRE)',
  ESP:    'IPsec encrypted tunnel',
  AH:     'IPsec auth header',
  OSPF:   'routing protocol',
  PIM:    'multicast routing',
  VRRP:   'router redundancy',
  SCTP:   'stream control transport',
};

// Returns just the country from a full location string like "Seoul, Gyeonggi-do, KR — AS4766 Korea Telecom"
function shortGeo(location: string): string {
  if (!location || location === 'resolving') return '';
  const withoutOrg = location.split(' — ')[0].trim();
  const parts = withoutOrg.split(', ');
  return parts[parts.length - 1]?.trim() || '';
}

// --- Subcomponents ---

function SidebarItem({ icon, label, active, onClick }: { icon: React.ReactNode, label: string, active?: boolean, onClick: () => void }) {
  return (
    <button 
      onClick={onClick}
      className={cn(
        "relative flex flex-col items-center gap-1.5 group transition-all",
        active ? "text-emerald-500" : "text-slate-500 hover:text-slate-300"
      )}
    >
      <div className={cn(
        "p-2.5 rounded-xl border border-transparent transition-all duration-300",
        active ? "bg-emerald-500/10 border-emerald-500/20 shadow-[0_0_15px_rgba(16,185,129,0.1)]" : "group-hover:bg-white/5"
      )}>
        {icon}
      </div>
      <span className={cn(
        "text-[9px] font-bold uppercase tracking-wider transition-all duration-300",
        active ? "opacity-100" : "opacity-60 group-hover:opacity-100 text-[8px]"
      )}>
        {label}
      </span>
      {active && (
        <motion.div 
          layoutId="sidebar-active"
          className="absolute -left-4 w-1 h-6 bg-emerald-500 rounded-r-full"
        />
      )}
    </button>
  );
}

function StatCard({ label, value, icon, trend, trendLabel, onClick, active }: { label: string, value: string, icon: React.ReactNode, trend?: string, trendLabel?: string, onClick?: () => void, active?: boolean }) {
  return (
    <div 
      onClick={onClick}
      className={cn(
        "bg-black/40 border rounded-3xl p-6 backdrop-blur-md relative overflow-hidden group hover:border-white/10 transition-all cursor-pointer",
        active ? "border-emerald-500/50 ring-1 ring-emerald-500/20" : "border-white/5"
      )}
    >
      <div className="flex items-center justify-between mb-4">
        <div className="p-2.5 rounded-xl bg-white/5 border border-white/5">
          {icon}
        </div>
        {trend && (
          <div className="text-right">
            <span className={cn(
              "text-[10px] font-bold px-2 py-0.5 rounded-full block",
              trend.includes('%') ? (trend.startsWith('+') ? "bg-emerald-500/10 text-emerald-500" : "bg-red-500/10 text-red-500") : "bg-white/5 text-slate-400"
            )}>
              {trend}
            </span>
            {trendLabel && <span className="text-[8px] text-slate-600 mt-1 uppercase tracking-wider block">{trendLabel}</span>}
          </div>
        )}
      </div>
      <p className="text-xs text-slate-500 font-medium">{label}</p>
      <p className="text-2xl font-bold text-white mt-1 tracking-tight">{value}</p>
      
      {/* Decorative pulse background */}
      <div className="absolute -right-4 -bottom-4 w-24 h-24 bg-white/[0.02] rounded-full blur-3xl group-hover:bg-white/[0.04] transition-colors" />
    </div>
  );
}

function MitigationLog({ app, action, desc, time }: { app: string, action: string, desc: string, time: string }) {
  return (
    <div className="p-3 bg-white/[0.03] border border-white/5 rounded-xl hover:bg-white/[0.05] transition-colors cursor-default">
      <div className="flex items-center justify-between mb-1">
        <span className="text-xs font-bold text-white tracking-tight">{app}</span>
        <span className="text-[8px] bg-red-500/10 text-red-500 px-1.5 py-0.5 rounded uppercase font-bold">{action}</span>
      </div>
      <p className="text-[10px] text-slate-500 line-clamp-1">{desc}</p>
      <p className="text-[8px] text-slate-600 mt-1 uppercase tracking-widest">{time}</p>
    </div>
  );
}
