import { Bell, Search, User, LogOut } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "@/contexts/AuthContext";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";

const TopBar = () => {
  const navigate = useNavigate();
  const { user, signOut } = useAuth();

  const { userRole } = useAuth();

  const displayName =
    user?.user_metadata?.full_name ||
    user?.email?.split("@")[0] ||
    "User";

  const roleLabel = userRole ? (userRole.charAt(0).toUpperCase() + userRole.slice(1)) : "";

  const handleLogout = async () => {
    await signOut();
    navigate("/login");
  };

  return (
    <header className="flex items-center justify-between px-6 py-3 border-b border-border bg-card">
      {/* Search */}
      <div className="relative flex-1 max-w-xl">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
        <input
          placeholder="Search vulnerabilities, assets, scans..."
          className="w-full bg-secondary rounded-md pl-10 pr-4 py-2 text-sm text-foreground placeholder:text-muted-foreground border border-border focus:outline-none focus:ring-1 focus:ring-primary"
        />
      </div>

      {/* Right side */}
      <div className="flex items-center gap-4 ml-6">
        <button
          onClick={() => navigate("/settings?tab=notifications")}
          className="relative text-muted-foreground hover:text-foreground transition-colors"
        >
          <Bell className="w-5 h-5" />
          <span className="absolute -top-1 -right-1 w-2 h-2 bg-primary rounded-full" />
        </button>

        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <button className="flex items-center gap-2 hover:opacity-80 transition-opacity">
              <div className="w-8 h-8 rounded-full bg-secondary flex items-center justify-center">
                <User className="w-4 h-4 text-muted-foreground" />
              </div>
              <div className="flex flex-col items-start leading-none">
                <span className="text-sm text-foreground font-medium">{displayName}</span>
                {roleLabel && (
                  <span className="text-[10px] text-muted-foreground font-normal mt-0.5 uppercase tracking-wider">
                    {roleLabel}
                  </span>
                )}
              </div>
            </button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-56">
            <div className="px-2 py-1.5 border-b border-border mb-1">
              <p className="text-xs font-medium text-foreground truncate">{user?.email}</p>
              <p className="text-[10px] text-muted-foreground uppercase mt-0.5">{roleLabel || 'Loading role...'}</p>
            </div>
            <DropdownMenuItem onClick={() => navigate("/settings")} className="cursor-pointer">
              <User className="w-4 h-4 mr-2" />
              Profile Settings
            </DropdownMenuItem>
            <DropdownMenuItem
              onClick={handleLogout}
              className="cursor-pointer text-muted-foreground hover:!text-red-400 transition-colors"
            >
              <LogOut className="w-4 h-4 mr-2" />
              Sign Out
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
    </header>
  );
};

export default TopBar;
