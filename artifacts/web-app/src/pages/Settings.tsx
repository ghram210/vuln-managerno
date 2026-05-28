import { useState, useEffect } from "react";
import { useSearchParams, useNavigate } from "react-router-dom";
import AppSidebar from "@/components/AppSidebar";
import TopBar from "@/components/TopBar";
import { cn } from "@/lib/utils";
import {
  User, Bell, Key, Save, LogOut,
  Globe, Plus, Trash2, CheckCircle2, Clock,
  AlertTriangle, Loader2, Copy, Check, RefreshCw, ShieldCheck,
} from "lucide-react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { supabase } from "@/integrations/supabase/client";
import { Switch } from "@/components/ui/switch";
import { toast } from "sonner";
import { useAuth } from "@/contexts/AuthContext";

const API_URL = import.meta.env.VITE_API_URL || "/api";

const tabs = [
  { key: "profile",       label: "Profile",       icon: User  },
  { key: "domains",       label: "My Domains",    icon: Globe },
  { key: "notifications", label: "Notifications", icon: Bell  },
  { key: "api-keys",      label: "API Keys",      icon: Key   },
];

interface Domain {
  id: string;
  user_id: string;
  domain: string;
  status: "pending" | "verified";
  token: string | null;
  created_at: string;
}

const Settings = () => {
  const [collapsed, setCollapsed]             = useState(false);
  const [searchParams]                        = useSearchParams();
  const [activeTab, setActiveTab]             = useState(searchParams.get("tab") || "profile");
  const { user, signOut, session, userRole }  = useAuth();
  const navigate                              = useNavigate();
  const [fullName, setFullName]               = useState("");
  const [email, setEmail]                     = useState("");
  const queryClient                           = useQueryClient();

  const [newDomain, setNewDomain]         = useState("");
  const [expanded, setExpanded]           = useState<string | null>(null);
  const [copiedId, setCopiedId]           = useState<string | null>(null);
  const [verifyingId, setVerifyingId]     = useState<string | null>(null);

  const isAdmin = userRole === "admin";

  useEffect(() => {
    if (user) {
      setFullName(user.user_metadata?.full_name || user.email?.split("@")[0] || "");
      setEmail(user.email || "");
    }
  }, [user]);

  useEffect(() => {
    const tab = searchParams.get("tab");
    if (tab) setActiveTab(tab);
  }, [searchParams]);

  const handleLogout = async () => { await signOut(); navigate("/login"); };

  // ── Notifications ──────────────────────────────────────────────────────────
  const { data: notifications } = useQuery({
    queryKey: ["notification_settings"],
    queryFn: async () => {
      const { data } = await supabase.from("notification_settings").select("*").order("sort_order");
      return data || [];
    },
  });

  const toggleMutation = useMutation({
    mutationFn: async ({ id, enabled }: { id: string; enabled: boolean }) => {
      const { error } = await supabase.from("notification_settings").update({ enabled }).eq("id", id);
      if (error) throw error;
    },
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["notification_settings"] }),
  });

  // ── Domains ────────────────────────────────────────────────────────────────
  const { data: domainsData, isLoading: domainsLoading } = useQuery({
    queryKey: ["user_domains"],
    queryFn: async () => {
      if (!session?.access_token) return { domains: [] };
      const res = await fetch(`${API_URL}/domains`, {
        headers: { Authorization: `Bearer ${session.access_token}` },
      });
      if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || "Failed to load domains");
      return res.json() as Promise<{ domains: Domain[] }>;
    },
    enabled: !!session?.access_token,
  });
  const domains = domainsData?.domains ?? [];

  const addDomain = useMutation({
    mutationFn: async (domain: string) => {
      const res = await fetch(`${API_URL}/domains`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${session?.access_token}` },
        body: JSON.stringify({ domain }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Failed to add domain");
      return data;
    },
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["user_domains"] });
      setNewDomain("");
      if (data.adminBypass) {
        toast.success("Domain added to your whitelist — ready to scan immediately.");
      } else {
        toast.success("Domain added. Verify ownership to enable scanning.");
      }
    },
    onError: (err: Error) => toast.error(err.message),
  });

  const deleteDomain = useMutation({
    mutationFn: async (id: string) => {
      const res = await fetch(`${API_URL}/domains/${id}`, {
        method: "DELETE",
        headers: { Authorization: `Bearer ${session?.access_token}` },
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Failed to delete");
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["user_domains"] });
      toast.success("Domain removed");
    },
    onError: (err: Error) => toast.error(err.message),
  });

  const handleVerify = async (row: Domain) => {
    setVerifyingId(row.id);
    try {
      const res = await fetch(`${API_URL}/domains/${row.id}/verify`, {
        method: "POST",
        headers: { Authorization: `Bearer ${session?.access_token}` },
      });
      const data = await res.json();
      if (data.verified) {
        toast.success("✅ Domain verified successfully! You can now scan it.");
        queryClient.invalidateQueries({ queryKey: ["user_domains"] });
        setExpanded(null);
      } else {
        toast.error(data.message || "Verification failed");
      }
    } catch {
      toast.error("Verification request failed");
    } finally {
      setVerifyingId(null);
    }
  };

  const copyToken = (token: string, id: string) => {
    navigator.clipboard.writeText(token);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
    toast.success("Token copied!");
  };

  return (
    <div className="flex h-screen bg-background">
      <AppSidebar collapsed={collapsed} onToggle={() => setCollapsed(!collapsed)} activePage="settings" />
      <div className="flex-1 flex flex-col overflow-hidden">
        <TopBar />
        <main className="flex-1 overflow-y-auto p-8">
          <h1 className="text-2xl font-bold text-foreground mb-1">Settings</h1>
          <p className="text-muted-foreground mb-6">Manage your account and preferences</p>

          {/* Tabs */}
          <div className="flex gap-2 mb-6 flex-wrap">
            {tabs.map(({ key, label, icon: Icon }) => (
              <button
                key={key}
                onClick={() => setActiveTab(key)}
                className={cn(
                  "flex items-center gap-2 px-4 py-2 rounded-full text-sm font-medium transition-colors",
                  activeTab === key
                    ? "bg-primary text-primary-foreground"
                    : "text-muted-foreground hover:text-foreground"
                )}
              >
                <Icon className="w-4 h-4" />
                {label}
              </button>
            ))}
          </div>

          {/* ── Profile ── */}
          {activeTab === "profile" && (
            <div className="bg-card border border-border rounded-xl p-6 max-w-3xl">
              <div className="flex items-center gap-4 mb-6">
                <div className="w-14 h-14 rounded-full bg-muted flex items-center justify-center">
                  <User className="w-7 h-7 text-muted-foreground" />
                </div>
                <div>
                  <p className="text-foreground font-semibold text-lg">{fullName || "User"}</p>
                  <p className="text-muted-foreground text-sm">{email}</p>
                </div>
              </div>
              <div className="grid grid-cols-2 gap-4 mb-6">
                <div>
                  <label className="text-sm text-muted-foreground mb-1 block">Full Name</label>
                  <input type="text" value={fullName} onChange={(e) => setFullName(e.target.value)}
                    className="w-full bg-background border border-border rounded-lg px-4 py-2.5 text-foreground focus:outline-none focus:border-primary" />
                </div>
                <div>
                  <label className="text-sm text-muted-foreground mb-1 block">Email</label>
                  <input type="email" value={email} onChange={(e) => setEmail(e.target.value)}
                    className="w-full bg-background border border-border rounded-lg px-4 py-2.5 text-foreground focus:outline-none focus:border-primary" />
                </div>
              </div>
              <div className="flex items-center gap-3">
                <button onClick={() => toast.success("Changes saved!")}
                  className="flex items-center gap-2 bg-primary text-primary-foreground px-5 py-2.5 rounded-lg font-medium hover:bg-primary/90 transition-colors">
                  <Save className="w-4 h-4" /> Save Changes
                </button>
                <button onClick={handleLogout}
                  className="flex items-center gap-2 border border-red-500/30 text-red-400 px-5 py-2.5 rounded-lg font-medium hover:bg-red-500/10 transition-colors">
                  <LogOut className="w-4 h-4" /> Sign Out
                </button>
              </div>
            </div>
          )}

          {/* ── My Domains ── */}
          {activeTab === "domains" && (
            <div className="max-w-3xl space-y-6">
              <div className="bg-card border border-border rounded-xl p-6">
                <div className="flex items-center gap-2 mb-2">
                  <Globe className="w-5 h-5 text-primary" />
                  <h2 className="text-lg font-bold text-foreground">
                    {isAdmin ? "Scan Whitelist (Admin)" : "Authorized Scan Domains"}
                  </h2>
                </div>

                {isAdmin ? (
                  <p className="text-muted-foreground text-sm mb-5">
                    As an admin, domains you add here are added <span className="text-primary font-semibold">immediately</span> to your
                    personal whitelist — no ownership verification required. You can scan them right away alongside the built-in targets.
                    Up to <span className="text-primary font-semibold">30 custom targets</span> allowed.
                  </p>
                ) : (
                  <p className="text-muted-foreground text-sm mb-5">
                    Register up to <span className="text-primary font-semibold">5 domains</span> that you own.
                    Each domain must pass an <span className="text-primary font-semibold">HTTP-01 ownership challenge</span> before scanning is permitted.
                  </p>
                )}

                {/* Warning — users only */}
                {!isAdmin && (
                  <div className="bg-amber-500/10 border border-amber-500/30 rounded-lg px-4 py-3 mb-6 flex gap-3">
                    <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                    <p className="text-amber-300 text-sm">
                      Only <strong>verified</strong> domains can be scanned. Scanning systems you do not own
                      is a serious legal and ethical violation.
                    </p>
                  </div>
                )}

                {/* Admin info banner */}
                {isAdmin && (
                  <div className="bg-primary/10 border border-primary/30 rounded-lg px-4 py-3 mb-6 flex gap-3">
                    <ShieldCheck className="w-4 h-4 text-primary shrink-0 mt-0.5" />
                    <p className="text-primary/90 text-sm">
                      You also have permanent access to the built-in targets: <span className="font-mono text-xs">testfire.net</span>, <span className="font-mono text-xs">testphp.vulnweb.com</span>, <span className="font-mono text-xs">scanme.nmap.org</span>, and more — no need to add them here.
                    </p>
                  </div>
                )}

                {domainsLoading ? (
                  <div className="flex items-center gap-2 text-muted-foreground py-4">
                    <Loader2 className="w-4 h-4 animate-spin" /> Loading domains…
                  </div>
                ) : (
                  <div className="space-y-3">
                    {domains.map((d, idx) => (
                      <div key={d.id} className="border border-border rounded-lg overflow-hidden">
                        {/* Domain row */}
                        <div className="flex items-center gap-3 px-4 py-3 bg-background">
                          <span className="text-xs text-muted-foreground w-5 shrink-0">{idx + 1}.</span>
                          <Globe className="w-4 h-4 text-muted-foreground shrink-0" />
                          <span className="text-foreground font-mono text-sm flex-1">{d.domain}</span>

                          {d.status === "verified" ? (
                            <span className="flex items-center gap-1 text-xs px-2 py-0.5 rounded-full bg-green-500/15 text-green-400 border border-green-500/20">
                              <CheckCircle2 className="w-3 h-3" />
                              {isAdmin ? "Whitelisted" : "Verified"}
                            </span>
                          ) : (
                            <span className="flex items-center gap-1 text-xs px-2 py-0.5 rounded-full bg-amber-500/15 text-amber-400 border border-amber-500/20">
                              <Clock className="w-3 h-3" /> Pending
                            </span>
                          )}

                          {/* Show verification CTA only for regular users with pending domains */}
                          {!isAdmin && d.status === "pending" && (
                            <button
                              onClick={() => setExpanded(expanded === d.id ? null : d.id)}
                              className="text-xs text-primary hover:underline px-2"
                            >
                              {expanded === d.id ? "Hide" : "How to verify"}
                            </button>
                          )}

                          <button
                            onClick={() => deleteDomain.mutate(d.id)}
                            disabled={deleteDomain.isPending}
                            className="text-muted-foreground hover:text-red-400 transition-colors ml-1"
                          >
                            <Trash2 className="w-4 h-4" />
                          </button>
                        </div>

                        {/* HTTP-01 verification steps — users only */}
                        {!isAdmin && expanded === d.id && d.status === "pending" && d.token && (
                          <div className="px-4 py-5 bg-muted/30 border-t border-border space-y-5">
                            {/* Step 1 */}
                            <div>
                              <p className="text-sm font-semibold text-foreground mb-1">
                                Step 1 — Create a verification file on your web server
                              </p>
                              <p className="text-sm text-muted-foreground mb-2">
                                The file must be publicly accessible at this URL:
                              </p>
                              <div className="bg-background border border-border rounded-lg px-3 py-2 font-mono text-xs text-primary break-all">
                                {`http://${d.domain}/.well-known/verify.txt`}
                              </div>
                            </div>

                            {/* Step 2 */}
                            <div>
                              <p className="text-sm font-semibold text-foreground mb-1">
                                Step 2 — Place this exact token as the file's content
                              </p>
                              <p className="text-xs text-muted-foreground mb-2">
                                The file must contain <strong>only</strong> this token — no spaces, no line breaks, nothing else.
                              </p>
                              <div className="flex items-center gap-2">
                                <div className="flex-1 bg-background border border-border rounded-lg px-3 py-2 font-mono text-xs text-foreground break-all select-all">
                                  {d.token}
                                </div>
                                <button
                                  onClick={() => copyToken(d.token!, d.id)}
                                  className="p-2 rounded-lg border border-border hover:border-primary transition-colors shrink-0"
                                >
                                  {copiedId === d.id
                                    ? <Check className="w-4 h-4 text-green-400" />
                                    : <Copy className="w-4 h-4 text-muted-foreground" />}
                                </button>
                              </div>
                            </div>

                            {/* How to create the file */}
                            <div className="bg-background border border-border rounded-lg px-4 py-3 text-xs space-y-2">
                              <p className="text-muted-foreground font-semibold">Example setup (Apache / Nginx / any server):</p>
                              <div className="font-mono text-foreground/80 space-y-1">
                                <p><span className="text-primary">mkdir -p</span> /var/www/html/.well-known</p>
                                <p><span className="text-primary">echo -n</span> "{d.token.slice(0, 16)}…" &gt; /var/www/html/.well-known/verify.txt</p>
                              </div>
                              <p className="text-muted-foreground pt-1">
                                You can also use any hosting control panel (cPanel, Plesk, etc.) to create the file at the path above.
                              </p>
                            </div>

                            {/* Step 3 */}
                            <div>
                              <p className="text-sm font-semibold text-foreground mb-2">
                                Step 3 — Click Verify once the file is live
                              </p>
                              <button
                                onClick={() => handleVerify(d)}
                                disabled={verifyingId === d.id}
                                className="flex items-center gap-2 bg-primary text-primary-foreground px-5 py-2 rounded-lg text-sm font-medium hover:bg-primary/90 transition-colors disabled:opacity-50"
                              >
                                {verifyingId === d.id
                                  ? <><Loader2 className="w-4 h-4 animate-spin" /> Verifying…</>
                                  : <><RefreshCw className="w-4 h-4" /> Verify Ownership</>}
                              </button>
                            </div>
                          </div>
                        )}
                      </div>
                    ))}

                    {/* Add domain input */}
                    {domains.length < (isAdmin ? 30 : 5) && (
                      <div className="flex items-center gap-2 mt-4">
                        <input
                          type="text"
                          value={newDomain}
                          onChange={(e) => setNewDomain(e.target.value)}
                          onKeyDown={(e) => {
                            if (e.key === "Enter" && newDomain.trim()) addDomain.mutate(newDomain.trim());
                          }}
                          placeholder={isAdmin ? "e.g. target.com  or  192.168.1.1" : "e.g. mycompany.com"}
                          className="flex-1 bg-background border border-border rounded-lg px-4 py-2.5 text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:border-primary font-mono"
                        />
                        <button
                          onClick={() => { if (newDomain.trim()) addDomain.mutate(newDomain.trim()); }}
                          disabled={addDomain.isPending || !newDomain.trim()}
                          className="flex items-center gap-2 bg-primary text-primary-foreground px-4 py-2.5 rounded-lg text-sm font-medium hover:bg-primary/90 transition-colors disabled:opacity-50 whitespace-nowrap"
                        >
                          {addDomain.isPending
                            ? <Loader2 className="w-4 h-4 animate-spin" />
                            : <Plus className="w-4 h-4" />}
                          {isAdmin ? "Add to Whitelist" : "Add Domain"}
                        </button>
                      </div>
                    )}

                    {domains.length === 0 && (
                      <p className="text-muted-foreground text-sm py-2">
                        {isAdmin
                          ? "No custom targets added yet. Built-in targets are always available."
                          : "No domains added yet. Add up to 5 domains that you own."}
                      </p>
                    )}

                    {domains.length >= (isAdmin ? 30 : 5) && (
                      <p className="text-xs text-muted-foreground px-1 pt-2">
                        Maximum of {isAdmin ? 30 : 5} entries reached. Delete one to add another.
                      </p>
                    )}

                    <p className="text-xs text-muted-foreground pt-2">
                      <span className="text-primary font-semibold">{domains.length}/{isAdmin ? 30 : 5}</span> custom{" "}
                      {isAdmin ? "targets" : "domains"} registered
                    </p>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* ── Notifications ── */}
          {activeTab === "notifications" && (
            <div className="bg-card border border-border rounded-xl p-6 max-w-3xl">
              <div className="space-y-6">
                {notifications?.map((n) => (
                  <div key={n.id} className="flex items-center justify-between">
                    <div>
                      <p className="text-foreground font-medium">{n.label}</p>
                      <p className="text-muted-foreground text-sm">{n.description}</p>
                    </div>
                    <Switch
                      checked={n.enabled}
                      onCheckedChange={(checked) => toggleMutation.mutate({ id: n.id, enabled: checked })}
                    />
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* ── API Keys ── */}
          {activeTab === "api-keys" && (
            <div className="bg-card border border-border rounded-xl p-6 max-w-3xl">
              <p className="text-muted-foreground">API key management coming soon.</p>
            </div>
          )}
        </main>
      </div>
    </div>
  );
};

export default Settings;
