"use client"

import { useState, useEffect } from "react"
import { usePathname } from "next/navigation"
import Link from "next/link"
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
} from "@/components/ui/sidebar"
import { Badge } from "@/components/ui/badge"
import { Shield, Search, Scan, Zap, FileText, Activity, Settings, Users, Home, LogOut } from "lucide-react"
import { createClient } from "@/lib/supabase"
import { useRouter } from "next/navigation"

const menuItems = [
  {
    title: "Dashboard",
    url: "/dashboard",
    icon: Home,
    roles: ["admin", "pentester", "viewer", "guest"],
  },
  {
    title: "Reconnaissance",
    url: "/dashboard/reconnaissance",
    icon: Search,
    roles: ["admin", "pentester", "guest"],
  },
  {
    title: "Scanning",
    url: "/dashboard/scanning",
    icon: Scan,
    roles: ["admin", "pentester"],
  },
  {
    title: "Exploitation",
    url: "/dashboard/exploitation",
    icon: Zap,
    roles: ["admin", "pentester"],
  },
  {
    title: "Reports",
    url: "/dashboard/reports",
    icon: FileText,
    roles: ["admin", "pentester", "viewer", "guest"],
  },
  {
    title: "Audit Logs",
    url: "/dashboard/audit-logs",
    icon: Activity,
    roles: ["admin"],
  },
  {
    title: "User Management",
    url: "/dashboard/users",
    icon: Users,
    roles: ["admin"],
  },
  {
    title: "Settings",
    url: "/dashboard/settings",
    icon: Settings,
    roles: ["admin", "pentester"],
  },
]

export function AppSidebar() {
  const pathname = usePathname()
  const router = useRouter()
  const [userRole, setUserRole] = useState<string>("guest")

  useEffect(() => {
    if (typeof window !== 'undefined') {
      const cookies = Object.fromEntries(
        document.cookie.split('; ').map(c => c.split('='))
      );
      setUserRole(cookies.userRole || "guest")
    }
  }, [])

  const handleLogout = async () => {
    const supabase = createClient()
    await supabase.auth.signOut()
    router.push("/auth/login")
  }

  const filteredMenuItems = menuItems.filter((item) => item.roles.includes(userRole))

  const getRoleBadgeColor = (role: string) => {
    switch (role) {
      case "admin":
        return "bg-red-600"
      case "pentester":
        return "bg-blue-600"
      case "viewer":
        return "bg-green-600"
      case "guest":
        return "bg-gray-600"
      default:
        return "bg-gray-600"
    }
  }

  return (
    <Sidebar variant="inset" className="border-slate-700">
      <SidebarHeader className="flex flex-col gap-2 border-b border-sidebar-border p-3 sm:p-4">
        <div className="flex items-center space-x-2 sm:space-x-3">
          <div className="p-1.5 sm:p-2 bg-purple-600 rounded-lg">
            <Shield className="h-4 w-4 sm:h-6 sm:w-6 text-white" />
          </div>
          <div>
            <h2 className="text-base sm:text-lg font-bold text-sidebar-foreground">PEN-T</h2>
            <p className="text-xs text-sidebar-foreground/70">Framework</p>
          </div>
        </div>
        <div className="mt-2 sm:mt-3">
          <Badge className="inline-flex items-center rounded-xl border px-2.5 py-0.5 font-semibold transition-colors focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2 border-transparent hover:bg-primary/80 bg-red-600 text-white text-xs">
            ADMIN
          </Badge>
        </div>
      </SidebarHeader>

      <SidebarContent className="bg-sidebar">
        <SidebarGroup>
          <SidebarGroupLabel className="text-sidebar-foreground/70 text-xs uppercase tracking-wider px-2">
            Security Modules
          </SidebarGroupLabel>
          <SidebarGroupContent>
            <SidebarMenu>
              {filteredMenuItems.map((item) => (
                <SidebarMenuItem key={item.title}>
                  <SidebarMenuButton
                    asChild
                    isActive={pathname === item.url}
                    className="text-sidebar-foreground hover:text-sidebar-accent-foreground hover:bg-sidebar-accent text-sm"
                  >
                    <Link href={item.url}>
                      <item.icon className="h-4 w-4" />
                      <span className="truncate">{item.title}</span>
                    </Link>
                  </SidebarMenuButton>
                </SidebarMenuItem>
              ))}
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>



        <SidebarGroup>
          <SidebarGroupLabel className="text-sidebar-foreground/70 text-xs uppercase tracking-wider px-2">
            System Status
          </SidebarGroupLabel>
          <SidebarGroupContent>
            <div className="px-3 py-2 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-sidebar-foreground text-xs sm:text-sm">Active Scans</span>
                <Badge variant="outline" className="border-green-600 text-green-400 text-xs">
                  3
                </Badge>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sidebar-foreground text-xs sm:text-sm">Queue</span>
                <Badge variant="outline" className="border-yellow-600 text-yellow-400 text-xs">
                  1
                </Badge>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sidebar-foreground text-xs sm:text-sm">System Load</span>
                <Badge variant="outline" className="border-blue-600 text-blue-400 text-xs">
                  Low
                </Badge>
              </div>
            </div>
          </SidebarGroupContent>
        </SidebarGroup>
      </SidebarContent>

      <SidebarFooter className="border-t border-slate-700 p-3 sm:p-4">
        <SidebarMenu>
          <SidebarMenuItem>
            <SidebarMenuButton
              onClick={handleLogout}
              className="text-sidebar-foreground hover:text-sidebar-accent-foreground hover:bg-sidebar-accent w-full text-sm"
            >
              <LogOut className="h-4 w-4" />
              <span>Sign Out</span>
            </SidebarMenuButton>
          </SidebarMenuItem>
        </SidebarMenu>
      </SidebarFooter>
    </Sidebar>
  )
}
