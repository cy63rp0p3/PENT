"use client"

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Search, Scan, Zap, FileText, Activity, Users, AlertTriangle } from "lucide-react"
import Link from "next/link";
import { useBackgroundScans } from "@/hooks/useBackgroundScans"
import { useEffect, useState } from "react"

export default function DashboardPage() {
  const { activeScans } = useBackgroundScans()
  const activeScanCount = activeScans.filter(scan => scan.status === 'running').length
  
  console.log('Dashboard - Active scans:', activeScans)
  console.log('Dashboard - Active scan count:', activeScanCount)
  const [userStats, setUserStats] = useState({
    total_users: 0,
    active_users: 0,
    pentesters: 0,
    admins: 0,
  });

  useEffect(() => {
    // Fetch user statistics from backend
    console.log("Fetching user stats...");
    fetch("http://localhost:8000/api/user/stats/")
      .then((res) => {
        console.log("Response status:", res.status);
        return res.json();
      })
      .then((data) => {
        console.log("User stats data:", data);
        setUserStats(data);
      })
      .catch((error) => {
        console.error("Failed to fetch user stats:", error);
        // Fallback to default values if API fails
        setUserStats({
          total_users: 0,
          active_users: 0,
          pentesters: 0,
          admins: 0,
        });
      });
  }, []);

  const stats = [
    { title: "Active Scans", value: activeScanCount, icon: Scan, color: "text-blue-400" },
    { title: "Vulnerabilities Found", value: "12", icon: AlertTriangle, color: "text-red-400" },
    { title: "Reports Generated", value: "8", icon: FileText, color: "text-green-400" },
    { title: "Total Users", value: userStats.total_users, icon: Users, color: "text-purple-400" },
  ]

  const recentActivity = [
    { action: "Port scan completed", target: "192.168.1.0/24", time: "2 minutes ago", status: "success" },
    { action: "Subdomain enumeration", target: "example.com", time: "15 minutes ago", status: "running" },
    { action: "Vulnerability scan", target: "10.0.0.1", time: "1 hour ago", status: "completed" },
    { action: "Report generated", target: "Security Assessment #001", time: "2 hours ago", status: "success" },
  ]

  return (
    <div className="space-y-4 sm:space-y-6">
      <div>
        <h1 className="text-2xl sm:text-3xl font-bold text-foreground mb-2">Dashboard</h1>
        <p className="text-muted-foreground text-sm sm:text-base">
          Welcome to PEN-T Framework - Your Security Testing Command Center
        </p>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 sm:gap-6">
        {stats.map((stat, index) => (
          <Card key={index}>
            <CardContent className="p-4 sm:p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-muted-foreground text-xs sm:text-sm">{stat.title}</p>
                  <p className="text-xl sm:text-2xl font-bold text-foreground">{stat.value}</p>
                </div>
                <stat.icon className={`h-6 w-6 sm:h-8 sm:w-8 ${stat.color}`} />
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-4 sm:gap-6">
        {/* Quick Actions */}
        <Card>
          <CardHeader>
            <CardTitle className="text-lg sm:text-xl">Quick Actions</CardTitle>
            <CardDescription className="text-sm">Start your security testing workflow</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 sm:gap-4">
              <Link href="/dashboard/reconnaissance">
                <div className="p-3 sm:p-4 bg-secondary rounded-xl hover:bg-accent cursor-pointer transition-colors">
                  <Search className="h-5 w-5 sm:h-6 sm:w-6 text-blue-400 mb-2" />
                  <h3 className="text-foreground font-medium text-sm sm:text-base">Reconnaissance</h3>
                  <p className="text-muted-foreground text-xs sm:text-sm">Start target discovery</p>
                </div>
              </Link>
              <Link href="/dashboard/scanning">
              <div className="p-3 sm:p-4 bg-secondary rounded-xl hover:bg-accent cursor-pointer transition-colors">
                <Scan className="h-5 w-5 sm:h-6 sm:w-6 text-green-400 mb-2" />
                <h3 className="text-foreground font-medium text-sm sm:text-base">Port Scan</h3>
                  <p className="text-muted-foreground text-xs sm:text-sm">Scan for open ports</p>
                </div>
              </Link>
              <Link href="/dashboard/scanning">
              <div className="p-3 sm:p-4 bg-secondary rounded-xl hover:bg-accent cursor-pointer transition-colors">
                <Zap className="h-5 w-5 sm:h-6 sm:w-6 text-yellow-400 mb-2" />
                <h3 className="text-foreground font-medium text-sm sm:text-base">Vulnerability Scan</h3>
                <p className="text-muted-foreground text-xs sm:text-sm">Find security issues</p>
              </div>
              </Link>
              <Link href="/dashboard/reports">
              <div className="p-3 sm:p-4 bg-secondary rounded-xl hover:bg-accent cursor-pointer transition-colors">
                <FileText className="h-5 w-5 sm:h-6 sm:w-6 text-purple-400 mb-2" />
                <h3 className="text-foreground font-medium text-sm sm:text-base">Generate Report</h3>
                <p className="text-muted-foreground text-xs sm:text-sm">Create assessment report</p>
              </div>
              </Link>
            </div>
          </CardContent>
        </Card>

        {/* Recent Activity */}
        <Card>
          <CardHeader>
            <CardTitle className="text-lg sm:text-xl">Recent Activity</CardTitle>
            <CardDescription className="text-sm">Latest security testing activities</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-3 sm:space-y-4">
              {recentActivity.map((activity, index) => (
                <div
                  key={index}
                  className="flex flex-col sm:flex-row sm:items-center justify-between p-3 bg-secondary rounded-xl space-y-2 sm:space-y-0"
                >
                  <div className="flex items-center space-x-3">
                    <Activity className="h-4 w-4 text-muted-foreground flex-shrink-0" />
                    <div className="min-w-0">
                      <p className="text-foreground text-sm font-medium truncate">{activity.action}</p>
                      <p className="text-muted-foreground text-xs truncate">{activity.target}</p>
                    </div>
                  </div>
                  <div className="flex items-center justify-between sm:flex-col sm:items-end">
                    <Badge
                      variant={
                        activity.status === "success"
                          ? "default"
                          : activity.status === "running"
                            ? "secondary"
                            : "outline"
                      }
                      className="mb-0 sm:mb-1 text-xs"
                    >
                      {activity.status}
                    </Badge>
                    <p className="text-muted-foreground text-xs">{activity.time}</p>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
