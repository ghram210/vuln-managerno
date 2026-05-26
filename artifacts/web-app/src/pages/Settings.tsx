import { useState, useEffect } from "react";
import { useSearchParams, useNavigate } from "react-router-dom";
import AppSidebar from "@/components/AppSidebar";
import TopBar from "@/components/TopBar";
import { cn } from "@/lib/utils";
import { User, Bell, Key, Save, LogOut, Globe, ShieldCheck, ShieldAlert, Trash2, CheckCircle, Loader2 } from "lucide-react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { supabase } from "@/integrations/supabase/client";
import { Switch } from "@/components/ui/switch";
import { toast } from "sonner";
import { useAuth } from "@/contexts/AuthContext";

const tabs = [
  { key: "profile", label: "Profile", icon: User },
  { key: "domains", label: "My Domains", icon: Globe },
  { key: "notifications", label: "Notifications", icon: Bell },
  { key: "api-keys", label: "API Keys", icon: Key },
];

const Settings = () => {
  const [collapsed, setCollapsed] = useState(false);
  const [searchParams] = useSearchParams();
  const [activeTab, setActiveTab] = useState(searchParams.get("tab") || "profile");
  const { user, signOut, session } = useAuth();
  const navigate = useNavigate();
  const [fullName, setFullName] = useState("");
  const [email, setEmail] = useState("");
  const [newDomain, setNewDomain] = useState("");
  const [isAddingDomain, setIsAddingDomain] = useState(false);
  const [verifyingId, setVerifyingId] = useState<string | null>(null);
  const queryClient = useQueryClient();

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

  const handleLogout = async () => {
    await signOut();
    navigate("/login");
  };

  const { data: notifications } = useQuery({
    queryKey: ["notification_settings"],
    queryFn: async () => {
      const { data } = await supabase
        .from("notification_settings")
        .select("*")
        .order("sort_order");
      return data || [];
    },
  });

  const toggleMutation = useMutation({
    mutationFn: async ({ id, enabled }: { id: string; enabled: boolean }) => {
      const { error } = await supabase
        .from("notification_settings")
        .update({ enabled })
        .eq("id", id);
      if (error) throw error;
    },
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["notification_settings"] }),
  });

  const { data: userDomains, isLoading: domainsLoading } = useQuery({
    queryKey: ["user_domains"],
    queryFn: async () => {
      const response = await fetch("/api/domains", {
        headers: {
          Authorization: `Bearer ${session?.access_token}`,
        },
      });
      if (!response.ok) throw new Error("Failed to fetch domains");
      return response.json();
    },
    enabled: !!session?.access_token,
  });

  const addDomainMutation = useMutation({
    mutationFn: async (domain: string) => {
      const response = await fetch("/api/domains", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${session?.access_token}`,
        },
        body: JSON.stringify({ domain }),
      });
      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.error || "Failed to add domain");
      }
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["user_domains"] });
      setNewDomain("");
      setIsAddingDomain(false);
      toast.success("Domain added successfully");
    },
    onError: (err: any) => {
      toast.error(err.message);
    },
  });

  const deleteDomainMutation = useMutation({
    mutationFn: async (id: string) => {
      const response = await fetch(`/api/domains/${id}`, {
        method: "DELETE",
        headers: {
          Authorization: `Bearer ${session?.access_token}`,
        },
      });
      if (!response.ok) throw new Error("Failed to delete domain");
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["user_domains"] });
      toast.success("Domain removed");
    },
  });

  const verifyDomainMutation = useMutation({
    mutationFn: async (id: string) => {
      setVerifyingId(id);
      const response = await fetch(`/api/domains/${id}/verify`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${session?.access_token}`,
        },
      });
      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.error || "Verification failed");
      }
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["user_domains"] });
      toast.success("Domain verified successfully!");
      setVerifyingId(null);
    },
    onError: (err: any) => {
      toast.error(err.message);
      setVerifyingId(null);
    },
  });

  return (
    <div className="flex min-h-screen bg-background">
      <AppSidebar collapsed={collapsed} onToggle={() => setCollapsed(!collapsed)} activePage="settings" />
      <div className="flex-1 flex flex-col min-h-screen">
        <TopBar />
        <main className="flex-1 p-8">
          <h1 className="text-2xl font-bold text-foreground mb-1">Settings</h1>
          <p className="text-muted-foreground mb-6">Manage your account and preferences</p>

          {/* Tabs */}
          <div className="flex gap-2 mb-6">
            {tabs.map((tab) => {
              const Icon = tab.icon;
              return (
                <button
                  key={tab.key}
                  onClick={() => setActiveTab(tab.key)}
                  className={cn(
                    "flex items-center gap-2 px-4 py-2 rounded-full text-sm font-medium transition-colors",
                    activeTab === tab.key
                      ? "bg-primary text-primary-foreground"
                      : "text-muted-foreground hover:text-foreground"
                  )}
                >
                  <Icon className="w-4 h-4" />
                  {tab.label}
                </button>
              );
            })}
          </div>

          {/* Profile Tab */}
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
                  <input
                    type="text"
                    value={fullName}
                    onChange={(e) => setFullName(e.target.value)}
                    className="w-full bg-background border border-border rounded-lg px-4 py-2.5 text-foreground focus:outline-none focus:border-primary"
                  />
                </div>
                <div>
                  <label className="text-sm text-muted-foreground mb-1 block">Email</label>
                  <input
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    className="w-full bg-background border border-border rounded-lg px-4 py-2.5 text-foreground focus:outline-none focus:border-primary"
                  />
                </div>
              </div>

              <div className="flex items-center gap-3">
                <button
                  onClick={() => toast.success("Changes saved!")}
                  className="flex items-center gap-2 bg-primary text-primary-foreground px-5 py-2.5 rounded-lg font-medium hover:bg-primary/90 transition-colors"
                >
                  <Save className="w-4 h-4" />
                  Save Changes
                </button>
                <button
                  onClick={handleLogout}
                  className="flex items-center gap-2 border border-red-500/30 text-red-400 px-5 py-2.5 rounded-lg font-medium hover:bg-red-500/10 transition-colors"
                >
                  <LogOut className="w-4 h-4" />
                  Sign Out
                </button>
              </div>
            </div>
          )}

          {/* Domains Tab */}
          {activeTab === "domains" && (
            <div className="max-w-4xl space-y-6">
              <div className="bg-card border border-border rounded-xl p-6">
                <div className="flex items-center justify-between mb-6">
                  <div>
                    <h2 className="text-lg font-semibold text-foreground">Verified Domains</h2>
                    <p className="text-sm text-muted-foreground mt-1">
                      Manage the domains you are authorized to scan. Max 5 domains.
                    </p>
                  </div>
                  {(userDomains?.length || 0) < 5 && (
                    <button
                      onClick={() => setIsAddingDomain(true)}
                      className="flex items-center gap-2 bg-primary text-primary-foreground px-4 py-2 rounded-lg text-sm font-medium hover:bg-primary/90 transition-colors"
                    >
                      <Globe className="w-4 h-4" />
                      Add Domain
                    </button>
                  )}
                </div>

                {isAddingDomain && (
                  <div className="mb-6 p-4 bg-muted/30 border border-border rounded-lg">
                    <div className="flex gap-3">
                      <input
                        type="text"
                        placeholder="e.g. example.com"
                        value={newDomain}
                        onChange={(e) => setNewDomain(e.target.value)}
                        className="flex-1 bg-background border border-border rounded-lg px-4 py-2 text-sm focus:outline-none focus:border-primary"
                      />
                      <button
                        onClick={() => addDomainMutation.mutate(newDomain)}
                        disabled={addDomainMutation.isPending || !newDomain.trim()}
                        className="bg-primary text-primary-foreground px-4 py-2 rounded-lg text-sm font-medium hover:bg-primary/90 disabled:opacity-50"
                      >
                        {addDomainMutation.isPending ? "Adding..." : "Confirm"}
                      </button>
                      <button
                        onClick={() => setIsAddingDomain(false)}
                        className="px-4 py-2 text-sm text-muted-foreground hover:text-foreground"
                      >
                        Cancel
                      </button>
                    </div>
                  </div>
                )}

                <div className="space-y-4">
                  {domainsLoading ? (
                    <p className="text-sm text-muted-foreground">Loading domains...</p>
                  ) : userDomains?.length === 0 ? (
                    <div className="text-center py-8 border border-dashed border-border rounded-lg">
                      <Globe className="w-8 h-8 text-muted-foreground mx-auto mb-2 opacity-50" />
                      <p className="text-sm text-muted-foreground">No domains added yet.</p>
                    </div>
                  ) : (
                    userDomains?.map((domain: any) => (
                      <div key={domain.id} className="border border-border rounded-lg p-4 bg-background/50">
                        <div className="flex items-center justify-between mb-4">
                          <div className="flex items-center gap-3">
                            <div className={cn(
                              "w-10 h-10 rounded-full flex items-center justify-center",
                              domain.isVerified ? "bg-green-500/10" : "bg-yellow-500/10"
                            )}>
                              {domain.isVerified ? (
                                <ShieldCheck className="w-5 h-5 text-green-500" />
                              ) : (
                                <ShieldAlert className="w-5 h-5 text-yellow-500" />
                              )}
                            </div>
                            <div>
                              <p className="font-medium text-foreground">{domain.domain}</p>
                              <p className="text-xs text-muted-foreground">
                                {domain.isVerified ? "Ownership Verified" : "Verification Pending"}
                              </p>
                            </div>
                          </div>
                          <div className="flex items-center gap-2">
                            {!domain.isVerified && (
                              <button
                                onClick={() => verifyDomainMutation.mutate(domain.id)}
                                disabled={verifyingId === domain.id}
                                className="flex items-center gap-2 bg-green-600/10 text-green-500 hover:bg-green-600/20 px-3 py-1.5 rounded text-xs font-medium transition-colors"
                              >
                                {verifyingId === domain.id ? (
                                  <Loader2 className="w-3 h-3 animate-spin" />
                                ) : (
                                  <CheckCircle className="w-3 h-3" />
                                )}
                                Verify Ownership
                              </button>
                            )}
                            <button
                              onClick={() => deleteDomainMutation.mutate(domain.id)}
                              className="p-2 text-muted-foreground hover:text-red-400 transition-colors"
                            >
                              <Trash2 className="w-4 h-4" />
                            </button>
                          </div>
                        </div>

                        {!domain.isVerified && (
                          <div className="mt-4 text-xs bg-muted/50 p-3 rounded border border-border">
                            <p className="font-semibold mb-2">How to verify:</p>
                            <ol className="list-decimal list-inside space-y-1.5 text-muted-foreground">
                              <li>Create a file named <code className="bg-background px-1 py-0.5 rounded border">verify.txt</code></li>
                              <li>Paste the following token inside: <code className="bg-background px-1 py-0.5 rounded border select-all font-mono">{domain.verificationToken}</code></li>
                              <li>Upload it to your server at: <code className="bg-background px-1 py-0.5 rounded border font-mono">http://{domain.domain}/verify.txt</code></li>
                              <li>Click the "Verify Ownership" button above.</li>
                            </ol>
                          </div>
                        )}
                      </div>
                    ))
                  )}
                </div>
              </div>
            </div>
          )}

          {/* Notifications Tab */}
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
                      onCheckedChange={(checked) =>
                        toggleMutation.mutate({ id: n.id, enabled: checked })
                      }
                    />
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* API Keys Tab */}
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
