import { useState, useEffect } from "react";
import {
  Globe, Terminal, Zap, Shield, Maximize2,
  Loader2, CheckCircle2, ShieldX, AlertTriangle,
} from "lucide-react";
import { useMutation } from "@tanstack/react-query";
import { supabase } from "@/integrations/supabase/client";
import { useNavigate } from "react-router-dom";
import { toast } from "sonner";
import AppSidebar from "@/components/AppSidebar";
import TopBar from "@/components/TopBar";
import { cn } from "@/lib/utils";
import { Checkbox } from "@/components/ui/checkbox";
import { useAuth } from "@/contexts/AuthContext";

const GATEWAY_URL = import.meta.env.VITE_GATEWAY_URL || "http://localhost:8090";
const API_URL     = import.meta.env.VITE_API_URL     || "/api";

const tools = [
  { key: "NMAP",   label: "Nmap",      desc: "Network discovery and port scanning",     icon: Globe     },
  { key: "SQLMAP", label: "SQLmap",    desc: "SQL injection detection",                  icon: Terminal  },
  { key: "FFUF",   label: "FFUF",      desc: "Fast web fuzzer for content discovery",    icon: Zap       },
  { key: "NIKTO",  label: "Nikto",     desc: "Web server vulnerability scanner",         icon: Shield    },
  { key: "FULL",   label: "Full Scan", desc: "Comprehensive scan using all tools",       icon: Maximize2 },
];

type AuthStatus = "idle" | "checking" | "allowed" | "blocked";

const NewScan = () => {
  const [collapsed, setCollapsed]             = useState(false);
  const [scanName, setScanName]               = useState("");
  const [target, setTarget]                   = useState("");
  const [description, setDescription]         = useState("");
  const [selectedTool, setSelectedTool]       = useState("");
  const [confirmOwnership,    setConfirmOwnership]    = useState(false);
  const [confirmNonMalicious, setConfirmNonMalicious] = useState(false);
  const [confirmNoDamage,     setConfirmNoDamage]     = useState(false);
  const [confirmLogging,      setConfirmLogging]      = useState(false);

  const [authStatus,  setAuthStatus]  = useState<AuthStatus>("idle");
  const [authMessage, setAuthMessage] = useState("");

  const navigate = useNavigate();
  const { session, userRole } = useAuth();
  const isAdmin = userRole === "admin";

  // ── Real-time domain authorization check (600 ms debounce) ───────────────
  useEffect(() => {
    if (!target.trim()) { setAuthStatus("idle"); setAuthMessage(""); return; }

    const timer = setTimeout(async () => {
      if (!session?.access_token) return;
      setAuthStatus("checking");
      try {
        const res  = await fetch(`${API_URL}/domains/check?target=${encodeURIComponent(target.trim())}`, {
          headers: { Authorization: `Bearer ${session.access_token}` },
        });
        const data = await res.json();
        if (res.ok && data.allowed) {
          setAuthStatus("allowed");
          setAuthMessage(
            data.reason === "admin_hardcoded_whitelist"
              ? "Built-in admin target — authorized"
              : data.reason === "admin_custom_domain"
              ? "Admin whitelist (custom) — authorized"
              : "Domain is verified and authorized for scanning"
          );
        } else {
          setAuthStatus("blocked");
          setAuthMessage(data.message || `"${data.domain}" is not authorized for scanning.`);
        }
      } catch {
        setAuthStatus("idle");
      }
    }, 600);

    return () => clearTimeout(timer);
  }, [target, session]);

  const mutation = useMutation({
    mutationFn: async () => {
      const { data: { session: s } } = await supabase.auth.getSession();
      if (!s?.access_token) throw new Error("Not authenticated. Please log in.");

      // Final server-side authorization gate
      const checkRes = await fetch(`${API_URL}/domains/check?target=${encodeURIComponent(target)}`, {
        headers: { Authorization: `Bearer ${s.access_token}` },
      });
      if (!checkRes.ok) {
        const err = await checkRes.json().catch(() => ({}));
        throw new Error(err.message || "⛔ Unauthorized domain — verify it in Settings → My Domains.");
      }

      const response = await fetch(`${GATEWAY_URL}/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${s.access_token}` },
        body: JSON.stringify({ name: scanName, target, tool: selectedTool, description }),
      });
      if (!response.ok) {
        const err = await response.json().catch(() => ({ detail: "Unknown error" }));
        throw new Error(err.detail || `Gateway error: ${response.status}`);
      }
      return response.json();
    },
    onSuccess: () => { toast.success("Scan started! Redirecting to results…"); navigate("/scan-results"); },
    onError: (err: Error) => toast.error(err.message || "Failed to start scan"),
  });

  const allConfirmed = confirmOwnership && confirmNonMalicious && confirmNoDamage && confirmLogging;
  const canSubmit    = !!scanName.trim() && !!target.trim() && !!selectedTool && allConfirmed && authStatus === "allowed" && !mutation.isPending;

  return (
    <div className="flex h-screen bg-background text-foreground">
      <AppSidebar collapsed={collapsed} onToggle={() => setCollapsed(!collapsed)} activePage="new-scan" />
      <div className="flex-1 flex flex-col overflow-hidden">
        <TopBar />
        <main className="flex-1 overflow-y-auto p-6">

          {/* Target Configuration */}
          <div className="bg-card border border-border rounded-xl p-6 mb-6">
            <div className="flex items-center gap-2 mb-6">
              <Globe className="w-5 h-5 text-primary" />
              <h2 className="text-lg font-semibold text-primary">Target Configuration</h2>
            </div>

            <div className="space-y-5">
              <div>
                <label className="text-sm text-muted-foreground mb-1.5 block">Scan Name</label>
                <input
                  value={scanName}
                  onChange={(e) => setScanName(e.target.value)}
                  placeholder="e.g. Production Server Scan"
                  className="w-full bg-background border border-border rounded-lg px-4 py-2.5 text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-primary"
                />
              </div>

              {/* Target with live auth feedback */}
              <div>
                <label className="text-sm text-muted-foreground mb-1.5 block">Target URL or IP Address</label>
                <div className="relative">
                  <input
                    value={target}
                    onChange={(e) => setTarget(e.target.value)}
                    placeholder={isAdmin ? "e.g. testphp.vulnweb.com  or  your-custom-target.com" : "e.g. https://mywebsite.com"}
                    className={cn(
                      "w-full bg-background border rounded-lg px-4 py-2.5 pr-10 text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 transition-colors",
                      authStatus === "allowed"  && "border-green-500/60 focus:ring-green-500/50",
                      authStatus === "blocked"  && "border-red-500/60 focus:ring-red-500/50",
                      (authStatus === "checking" || authStatus === "idle") && "border-primary/50 focus:ring-primary",
                    )}
                  />
                  <div className="absolute right-3 top-1/2 -translate-y-1/2">
                    {authStatus === "checking" && <Loader2     className="w-4 h-4 animate-spin text-muted-foreground" />}
                    {authStatus === "allowed"  && <CheckCircle2 className="w-4 h-4 text-green-400" />}
                    {authStatus === "blocked"  && <ShieldX     className="w-4 h-4 text-red-400" />}
                  </div>
                </div>

                {authStatus === "allowed" && (
                  <p className="mt-1.5 text-xs text-green-400 flex items-center gap-1">
                    <CheckCircle2 className="w-3 h-3" /> {authMessage}
                  </p>
                )}

                {authStatus === "idle" && !target && (
                  <p className="mt-1.5 text-xs text-muted-foreground">
                    {isAdmin
                      ? "You can scan any built-in target or custom domain you have added to your whitelist."
                      : "Only domains you have added and verified in Settings → My Domains are allowed."}
                  </p>
                )}

                {authStatus === "blocked" && (
                  <div className="mt-3 bg-red-500/10 border border-red-500/30 rounded-lg p-4">
                    <div className="flex items-start gap-3">
                      <ShieldX className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
                      <div>
                        <p className="text-red-400 font-semibold text-sm mb-1">Access Denied — Unauthorized Domain</p>
                        <p className="text-red-300/80 text-xs leading-relaxed">{authMessage}</p>
                      </div>
                    </div>
                  </div>
                )}
              </div>

              <div>
                <label className="text-sm text-muted-foreground mb-1.5 block">Description (optional)</label>
                <input
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  placeholder="Brief description of this scan"
                  className="w-full bg-background border border-border rounded-lg px-4 py-2.5 text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-primary"
                />
              </div>
            </div>

            {/* Pre-Scan Confirmations */}
            <div className="pt-8 border-t border-border mt-8">
              <div className="flex items-center gap-2 mb-6">
                <CheckCircle2 className="w-5 h-5 text-primary" />
                <h2 className="text-lg font-bold text-primary uppercase tracking-tight">Pre-Scan Confirmation</h2>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-x-8 gap-y-6">
                {[
                  {
                    id: "ownership",
                    checked: confirmOwnership,
                    set: setConfirmOwnership,
                    text: "I certify that I own this target or have explicit, written authorization to perform security testing.",
                  },
                  {
                    id: "damage",
                    checked: confirmNoDamage,
                    set: setConfirmNoDamage,
                    text: "I agree not to utilize these tools to cause any intentional damage to the target infrastructure.",
                  },
                  {
                    id: "malicious",
                    checked: confirmNonMalicious,
                    set: setConfirmNonMalicious,
                    text: "I agree not to use the scan results for any unauthorized or malicious activities.",
                  },
                  {
                    id: "logging",
                    checked: confirmLogging,
                    set: setConfirmLogging,
                    text: "I acknowledge that scanning activities may be logged by the target's security systems.",
                  },
                ].map(({ id, checked, set, text }) => (
                  <div key={id} className="flex items-start space-x-3 group">
                    <Checkbox
                      id={id}
                      checked={checked}
                      onCheckedChange={(v) => set(v === true)}
                      className="mt-1 border-primary data-[state=checked]:bg-primary data-[state=checked]:text-primary-foreground"
                    />
                    <label
                      htmlFor={id}
                      className="text-sm leading-relaxed text-muted-foreground group-hover:text-foreground transition-colors cursor-pointer"
                    >
                      {text}
                    </label>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Tool Selection */}
          <div className="bg-card border border-border rounded-xl p-6 mb-6">
            <div className="flex items-center gap-2 mb-4">
              <Terminal className="w-5 h-5 text-muted-foreground" />
              <h2 className="text-lg font-semibold">Select Scan Tool</h2>
            </div>
            <div className="grid grid-cols-3 gap-4">
              {tools.map(({ key, label, desc, icon: Icon }) => {
                const active = selectedTool === key;
                return (
                  <button
                    key={key}
                    onClick={() => setSelectedTool(key)}
                    className={cn(
                      "flex flex-col items-start gap-3 p-5 rounded-xl border transition-all text-left",
                      active
                        ? "border-primary bg-primary/10"
                        : "border-border bg-card hover:border-muted-foreground"
                    )}
                  >
                    <Icon className={cn("w-6 h-6", active ? "text-primary" : "text-primary/60")} />
                    <div>
                      <p className="font-medium text-sm">{label}</p>
                      <p className="text-xs text-muted-foreground mt-1">{desc}</p>
                    </div>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Blocked warning */}
          {authStatus === "blocked" && (
            <div className="bg-red-500/10 border border-red-500/40 rounded-xl p-5 mb-4 flex items-start gap-4">
              <AlertTriangle className="w-6 h-6 text-red-400 shrink-0 mt-0.5" />
              <div>
                <p className="text-red-400 font-bold text-base mb-1">⛔ Domain Not Authorized</p>
                <p className="text-red-300/80 text-sm leading-relaxed">
                  {isAdmin
                    ? "Add this domain to your whitelist via Settings → My Domains to enable scanning."
                    : "Go to Settings → My Domains, add this domain, and complete the ownership verification."}
                </p>
              </div>
            </div>
          )}

          {/* Submit */}
          <button
            disabled={!canSubmit}
            onClick={() => {
              if (!canSubmit) {
                if (authStatus === "blocked")
                  toast.error(isAdmin ? "Add this domain to your whitelist first" : "Verify the domain in Settings → My Domains");
                else if (!scanName.trim() || !target.trim() || !selectedTool)
                  toast.error("Fill in Scan Name, Target, and select a tool");
                else if (!allConfirmed)
                  toast.error("Acknowledge all pre-scan confirmations");
                else if (authStatus !== "allowed")
                  toast.error("Enter a valid authorized target");
                return;
              }
              mutation.mutate();
            }}
            className={cn(
              "flex items-center gap-2 px-8 py-3 rounded-lg font-medium text-sm transition-all",
              canSubmit
                ? "bg-primary text-primary-foreground hover:bg-primary/90"
                : "bg-muted text-muted-foreground cursor-not-allowed opacity-50"
            )}
          >
            {mutation.isPending
              ? <><Loader2 className="w-4 h-4 animate-spin" /> Starting Scan…</>
              : <><Globe className="w-4 h-4" /> Start Scan</>}
          </button>

          {mutation.isPending && (
            <div className="bg-card border border-primary/30 rounded-xl p-5 mt-4">
              <div className="flex items-center gap-3 mb-2">
                <div className="w-3 h-3 bg-primary rounded-full animate-pulse" />
                <p className="text-primary font-semibold">Dispatching Scan…</p>
              </div>
              <p className="text-muted-foreground text-sm">
                Sending scan request for <span className="text-foreground font-mono">{target}</span> to the gateway.
              </p>
            </div>
          )}

          <div className="mt-4 text-xs text-muted-foreground bg-muted/30 rounded-lg px-4 py-3 border border-border">
            <strong>Note:</strong> Scans run in the background. The Scan Results page polls for updates automatically every 5 seconds.
          </div>
        </main>
      </div>
    </div>
  );
};

export default NewScan;
