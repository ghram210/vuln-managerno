import { useState } from "react";
import AppSidebar from "@/components/AppSidebar";
import TopBar from "@/components/TopBar";
import { Users, Scan, Bug, Activity, UserPlus, Send, FileText, Trash2, Copy, Check, AlertTriangle, Loader2, Wifi, WifiOff } from "lucide-react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { supabase } from "@/integrations/supabase/client";
import { toast } from "sonner";
import { useAuth } from "@/contexts/AuthContext";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";

const AdminPanel = () => {
  const [collapsed, setCollapsed] = useState(false);
  const [showInvite, setShowInvite] = useState(false);
  const [inviteEmail, setInviteEmail] = useState("");
  const [generatedLink, setGeneratedLink] = useState("");
  const [copied, setCopied] = useState(false);
  const [isGeneratingInvite, setIsGeneratingInvite] = useState(false);
  const [userToDelete, setUserToDelete] = useState<{ id: string, name: string } | null>(null);
  const [isInviteDialogOpen, setIsInviteDialogOpen] = useState(false);
  const { userRole, session } = useAuth();
  const queryClient = useQueryClient();

  const { data: apiHealth } = useQuery({
    queryKey: ["api-health"],
    queryFn: async () => {
      try {
        const res = await fetch("/api/healthz");
        return res.ok;
      } catch {
        return false;
      }
    },
    refetchInterval: 10000,
  });

  const { data: users } = useQuery({
    queryKey: ["admin_users"],
    queryFn: async () => {
      const { data, error } = await supabase.from("admin_users").select("*").order("joined_at", { ascending: false });
      if (error) console.error("Error fetching users:", error);
      return data || [];
    },
  });

  const { data: scanResults } = useQuery({
    queryKey: ["scan_results"],
    queryFn: async () => {
      const { data } = await supabase
        .from("scan_results")
        .select("*")
        .order("created_at", { ascending: false });
      return (data as Array<Record<string, any>>) || [];
    },
  });

  const scanUserIds = Array.from(
    new Set(
      (scanResults || [])
        .map((s) => (s.user_id as string | null) || "")
        .filter((v) => v.length > 0)
    )
  );

  const { data: userIdToEmail } = useQuery({
    queryKey: ["scan_creator_emails", scanUserIds],
    enabled: scanUserIds.length > 0,
    queryFn: async () => {
      const { data, error } = await (supabase.rpc as any)("get_user_emails", {
        user_ids: scanUserIds,
      });
      if (error) {
        console.warn("get_user_emails RPC failed:", error.message);
        return {} as Record<string, string>;
      }
      const map: Record<string, string> = {};
      for (const row of (data || []) as Array<{ user_id: string; email: string }>) {
        if (row.user_id && row.email) map[row.user_id] = row.email;
      }
      return map;
    },
  });

  const { data: vulnCount } = useQuery({
    queryKey: ["vulnerabilities_count"],
    queryFn: async () => {
      const { count } = await supabase.from("vulnerabilities").select("*", { count: "exact", head: true });
      return count || 0;
    },
  });

  const { data: systemLogs } = useQuery({
    queryKey: ["system_logs"],
    queryFn: async () => {
      const { data } = await supabase.from("system_logs").select("*").order("sort_order");
      return data || [];
    },
  });

  const removeUserMutation = useMutation({
    mutationFn: async (userId: string) => {
      console.log(`Attempting to remove user via API: ${userId}`);
      if (!session?.access_token) throw new Error("Not authenticated");

      const res = await fetch(`/api/admin/users/${userId}`, {
        method: "DELETE",
        headers: {
          Authorization: `Bearer ${session.access_token}`,
        },
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || `HTTP ${res.status}: Failed to delete user`);
      }
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["admin_users"] });
      toast.success("User removed successfully");
    },
    onError: (err: any) => {
      console.error("Removal mutation failed:", err);
      toast.error(`Failed to remove user: ${err.message || "Unknown error"}`);
    },
  });

  const activeScans = scanResults?.filter((s) => s.status === "running").length || 0;

  const emailToName: Record<string, string> = {};
  for (const u of users || []) {
    if (u.email) emailToName[u.email.toLowerCase()] = u.name || u.email;
  }

  const getCreatedBy = (scan: Record<string, any>): string => {
    const userId: string = scan.user_id || "";
    if (!userId) return "Unknown";
    const email = userIdToEmail?.[userId];
    if (email) {
      return emailToName[email.toLowerCase()] || email;
    }
    return "Unknown";
  };

  const stats = [
    { label: "TOTAL USERS", value: users?.length || 0, icon: Users, color: "text-primary" },
    { label: "TOTAL SCANS", value: scanResults?.length || 0, icon: Scan, color: "text-primary" },
    { label: "VULNERABILITIES", value: vulnCount, icon: Bug, color: "text-primary" },
    { label: "ACTIVE SCANS", value: activeScans, icon: Activity, color: "text-chart-4" },
  ];

  const handleGenerateInvite = async () => {
    if (!session?.access_token) {
      toast.error("Not authenticated in UI");
      return;
    }
    setIsGeneratingInvite(true);
    console.log("Generating invitation link for:", inviteEmail || "anyone");
    try {
      const res = await fetch("/api/invitations", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${session.access_token}`,
        },
        body: JSON.stringify({ email: inviteEmail || null }),
      });

      const data = await res.json();
      console.log("Invitation API response:", { status: res.status, data });

      if (!res.ok) {
        throw new Error(data.error || `HTTP ${res.status}: Invitation failed`);
      }

      const link = `${window.location.origin}/invite/${data.token}`;
      setGeneratedLink(link);
      setIsInviteDialogOpen(true);
      toast.success("Invitation link generated");
    } catch (err: any) {
      console.error("handleGenerateInvite caught error:", err);
      toast.error(`Invitation Error: ${err.message}`);
    } finally {
      setIsGeneratingInvite(false);
    }
  };

  const handleCopyLink = () => {
    navigator.clipboard.writeText(generatedLink);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
    toast.success("Link copied to clipboard");
  };

  const formatDate = (dateStr: string) => {
    const d = new Date(dateStr);
    return d.toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" });
  };

  const formatDateTime = (dateStr: string) => {
    const d = new Date(dateStr);
    return `${d.toLocaleDateString("en-US", { month: "short", day: "numeric" })}, ${d.toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit", hour12: false })}`;
  };

  return (
    <div className="flex h-screen overflow-hidden">
      <AppSidebar collapsed={collapsed} onToggle={() => setCollapsed(!collapsed)} activePage="admin" />
      <div className="flex-1 flex flex-col overflow-hidden">
        <TopBar />
        <main className="flex-1 overflow-y-auto p-8">
          <div className="flex items-center justify-between mb-6">
            <div>
              <div className="flex items-center gap-3 mb-1">
                <h1 className="text-2xl font-bold text-foreground">Admin Panel</h1>
                <div className={`flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[10px] font-bold border ${apiHealth ? "bg-green-500/10 text-green-400 border-green-500/20" : "bg-red-500/10 text-red-400 border-red-500/20"}`}>
                  {apiHealth ? <Wifi className="w-3 h-3" /> : <WifiOff className="w-3 h-3" />}
                  API {apiHealth ? "ONLINE" : "OFFLINE"}
                </div>
              </div>
              <p className="text-muted-foreground">System administration and user management</p>
            </div>
            <button
              onClick={() => setShowInvite(!showInvite)}
              className="flex items-center gap-2 bg-primary text-primary-foreground px-5 py-2.5 rounded-lg font-medium hover:bg-primary/90 transition-colors"
            >
              <UserPlus className="w-4 h-4" />
              Invite User
            </button>
          </div>

          {showInvite && (
            <div className="bg-card border border-border rounded-xl p-5 mb-6">
              <div className="flex items-end gap-4">
                <div className="flex-1">
                  <label className="text-sm text-muted-foreground mb-1 block">Email (optional)</label>
                  <input
                    type="email"
                    placeholder="user@example.com"
                    value={inviteEmail}
                    onChange={(e) => setInviteEmail(e.target.value)}
                    className="w-full bg-background border border-border rounded-lg px-4 py-2.5 text-foreground focus:outline-none focus:border-primary"
                  />
                </div>
                <button
                  onClick={handleGenerateInvite}
                  disabled={isGeneratingInvite}
                  className="flex items-center gap-2 bg-primary text-primary-foreground px-5 py-2.5 rounded-lg font-medium hover:bg-primary/90 transition-colors whitespace-nowrap disabled:opacity-50"
                >
                  {isGeneratingInvite ? <Loader2 className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4" />}
                  Generate Link
                </button>
                <button
                  onClick={() => { setShowInvite(false); setInviteEmail(""); }}
                  className="px-4 py-2.5 rounded-lg border border-border text-muted-foreground hover:text-foreground transition-colors"
                >
                  Cancel
                </button>
              </div>
            </div>
          )}

          <div className="grid grid-cols-4 gap-4 mb-6">
            {stats.map((stat) => {
              const Icon = stat.icon;
              return (
                <div key={stat.label} className="bg-card border border-border rounded-xl p-5">
                  <div className="flex items-center justify-between mb-3">
                    <p className="text-xs text-muted-foreground font-semibold tracking-wider">{stat.label}</p>
                    <Icon className={`w-5 h-5 ${stat.color}`} />
                  </div>
                  <p className="text-3xl font-bold text-foreground">{stat.value}</p>
                </div>
              );
            })}
          </div>

          <div className="bg-card border border-border rounded-xl p-5 mb-6">
            <h2 className="text-foreground font-semibold mb-4">User Management</h2>
            <table className="w-full">
              <thead>
                <tr className="text-muted-foreground text-xs uppercase tracking-wider">
                  <th className="text-left py-3 px-2">Name</th>
                  <th className="text-left py-3 px-2">Email</th>
                  <th className="text-left py-3 px-2">Role</th>
                  <th className="text-left py-3 px-2">Joined</th>
                  {userRole === "admin" && <th className="text-left py-3 px-2">Actions</th>}
                </tr>
              </thead>
              <tbody>
                {users?.map((user) => (
                  <tr key={user.id} className="border-t border-border">
                    <td className="py-3 px-2 text-foreground font-medium">{user.name}</td>
                    <td className="py-3 px-2 text-muted-foreground">{user.email}</td>
                    <td className="py-3 px-2">
                      <span
                        className={`text-xs px-2.5 py-1 rounded font-medium ${
                          user.role === "Admin"
                            ? "bg-primary/20 text-primary"
                            : "bg-green-500/20 text-green-400"
                        }`}
                      >
                        {user.role}
                      </span>
                    </td>
                    <td className="py-3 px-2 text-muted-foreground">{formatDate(user.joined_at)}</td>
                    {userRole === "admin" && (
                      <td className="py-3 px-2">
                        {user.role === "User" && (
                          <button
                            onClick={() => setUserToDelete({ id: user.id, name: user.name || user.email })}
                            className="flex items-center gap-1.5 text-muted-foreground hover:text-red-400 transition-colors text-sm"
                          >
                            <Trash2 className="w-4 h-4" />
                            Remove
                          </button>
                        )}
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Recent Scans */}
          <div className="bg-card border border-border rounded-xl p-5 mb-6">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-foreground font-semibold">Recent Scans (All Users)</h2>
              {scanResults && scanResults.length > 7 && (
                <span className="text-xs text-muted-foreground">
                  Showing {scanResults.length} scans — scroll inside table
                </span>
              )}
            </div>
            <div className="overflow-y-auto" style={{ maxHeight: "26rem" }}>
              <table className="w-full">
                <thead className="sticky top-0 bg-card z-10">
                  <tr className="text-muted-foreground text-xs uppercase tracking-wider">
                    <th className="text-left py-3 px-2">Name</th>
                    <th className="text-left py-3 px-2">Target</th>
                    <th className="text-left py-3 px-2">Tool</th>
                    <th className="text-left py-3 px-2">Created By</th>
                    <th className="text-left py-3 px-2">Date</th>
                  </tr>
                </thead>
                <tbody>
                  {scanResults?.map((scan) => (
                    <tr key={scan.id} className="border-t border-border">
                      <td className="py-3 px-2 text-foreground font-medium">{scan.name}</td>
                      <td className="py-3 px-2 text-muted-foreground text-sm">{scan.target}</td>
                      <td className="py-3 px-2 text-primary font-semibold text-sm">{scan.tool.toUpperCase()}</td>
                      <td className="py-3 px-2 text-muted-foreground text-sm">{getCreatedBy(scan)}</td>
                      <td className="py-3 px-2 text-muted-foreground text-sm">{formatDateTime(scan.created_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* System Logs */}
          <div className="bg-card border border-border rounded-xl p-5">
            <div className="flex items-center gap-2 mb-4">
              <FileText className="w-4 h-4 text-muted-foreground" />
              <h2 className="text-foreground font-semibold">System Logs</h2>
            </div>
            <div className="bg-[#0a0a0a] rounded-lg p-4 font-mono text-sm space-y-1">
              {systemLogs?.map((log) => (
                <p key={log.id}>
                  <span className="text-green-400">[{new Date(log.timestamp).toISOString()}]</span>{" "}
                  <span className="text-muted-foreground">{log.message}</span>
                </p>
              ))}
            </div>
          </div>
        </main>
      </div>

      {/* Invitation Link Dialog */}
      <Dialog open={isInviteDialogOpen} onOpenChange={setIsInviteDialogOpen}>
        <DialogContent className="sm:max-w-md bg-card border-border">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-foreground">
              <UserPlus className="w-5 h-5 text-primary" />
              Invitation Link Generated
            </DialogTitle>
            <DialogDescription className="text-muted-foreground">
              Copy this link and send it to the user. It expires in 7 days.
            </DialogDescription>
          </DialogHeader>
          <div className="flex items-center space-x-2 mt-4">
            <div className="grid flex-1 gap-2">
              <div className="bg-muted p-3 rounded-lg font-mono text-sm break-all text-foreground border border-border">
                {generatedLink}
              </div>
            </div>
            <Button
              onClick={handleCopyLink}
              className="shrink-0 flex gap-2"
            >
              {copied ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
              {copied ? "Copied" : "Copy"}
            </Button>
          </div>
          <DialogFooter className="sm:justify-start mt-6">
            <Button
              type="button"
              variant="secondary"
              onClick={() => {
                setIsInviteDialogOpen(false);
                setShowInvite(false);
                setInviteEmail("");
                setGeneratedLink("");
              }}
            >
              Close
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Remove User Confirmation */}
      <AlertDialog open={!!userToDelete} onOpenChange={(open) => !open && setUserToDelete(null)}>
        <AlertDialogContent className="bg-card border-border">
          <AlertDialogHeader>
            <AlertDialogTitle className="flex items-center gap-2 text-foreground">
              <AlertTriangle className="w-5 h-5 text-destructive" />
              Confirm User Removal
            </AlertDialogTitle>
            <AlertDialogDescription className="text-muted-foreground">
              Are you sure you want to remove <span className="font-semibold text-foreground">{userToDelete?.name}</span>?
              This action will revoke all access for this user. This cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel className="bg-muted text-foreground hover:bg-muted/80 border-none">Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => {
                if (userToDelete) {
                  removeUserMutation.mutate(userToDelete.id);
                  setUserToDelete(null);
                }
              }}
              className="bg-destructive text-white hover:bg-destructive/90 border-none"
            >
              Remove User
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
};

export default AdminPanel;
