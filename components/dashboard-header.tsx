"use client"

import { useEffect, useState } from "react"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Separator } from "@/components/ui/separator"
import { Bell, Moon, Sun, User, Play, CheckCircle, XCircle, Eye, X, Trash2 } from "lucide-react"
import { CustomSidebarTrigger } from "./custom-sidebar-trigger"
import { useBackgroundScans } from "@/hooks/useBackgroundScans"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { Progress } from "@/components/ui/progress"
import Link from "next/link"

export function DashboardHeader() {
  const [darkMode, setDarkMode] = useState(true)
  const { activeScans, removeScan } = useBackgroundScans()
  
  // Calculate notifications from background scans
  const runningScans = activeScans.filter(scan => scan.status === 'running')
  const completedScans = activeScans.filter(scan => scan.status === 'completed')
  const notifications = runningScans.length + completedScans.length

  useEffect(() => {
    if (typeof window !== "undefined") {
      document.documentElement.setAttribute("data-theme", darkMode ? "dark" : "light")
    }
  }, [darkMode])

  const toggleDarkMode = () => {
    setDarkMode((prev) => !prev)
  }

  const formatTime = (timestamp: number) => {
    const date = new Date(timestamp)
    return date.toLocaleTimeString('en-US', { 
      hour: '2-digit', 
      minute: '2-digit' 
    })
  }

  const getScanTypeLabel = (scanType: string) => {
    switch (scanType) {
      case 'whois': return 'WHOIS Lookup'
      case 'dns': return 'DNS Lookup'
      case 'subdomain': return 'Subdomain Enumeration'
      default: return scanType
    }
  }

  const clearAllCompletedScans = () => {
    completedScans.forEach(scan => {
      removeScan(scan.scanId)
    })
  }

  return (
    <header className="flex h-16 shrink-0 items-center gap-2 border-b border-border px-4 bg-background">
      <CustomSidebarTrigger />
      <div className="flex items-center justify-between w-full">
        <div className="hidden sm:block">
          <h1 className="text-base sm:text-lg font-semibold text-foreground">Security Dashboard</h1>
          <p className="text-xs sm:text-sm text-muted-foreground">
            {new Date().toLocaleDateString("en-US", {
              weekday: "long",
              year: "numeric",
              month: "long",
              day: "numeric",
            })}
          </p>
        </div>
        <div className="sm:hidden">
          <h1 className="text-sm font-semibold text-foreground">Dashboard</h1>
        </div>

        <div className="flex items-center space-x-2 sm:space-x-4">
          <Button
            variant="ghost"
            size="icon"
            onClick={toggleDarkMode}
            className="text-muted-foreground hover:text-foreground hover:bg-accent h-8 w-8 sm:h-10 sm:w-10 rounded-full"
          >
            {darkMode ? <Sun className="h-3 w-3 sm:h-4 sm:w-4" /> : <Moon className="h-3 w-3 sm:h-4 sm:w-4" />}
          </Button>

          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button
                variant="ghost"
                size="icon"
                className="text-muted-foreground hover:text-foreground hover:bg-accent relative h-8 w-8 sm:h-10 sm:w-10 rounded-xl border border-border"
              >
                <Bell className="h-3 w-3 sm:h-4 sm:w-4" />
                {notifications > 0 && (
                  <Badge className="absolute -top-1 -right-1 h-4 w-4 sm:h-5 sm:w-5 rounded-full bg-red-600 text-white text-xs flex items-center justify-center p-0">
                    {notifications}
                  </Badge>
                )}
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-80 rounded-xl border border-border">
              <DropdownMenuLabel className="flex items-center justify-between">
                <span>Scan Notifications</span>
                <div className="flex items-center gap-2">
                  <Badge variant="outline" className="text-xs">
                    {notifications} total
                  </Badge>
                  {completedScans.length > 0 && (
                    <Button
                      variant="ghost"
                      size="sm"
                      className="h-6 px-2 text-xs text-muted-foreground hover:text-foreground rounded-xl border border-border hover:bg-accent"
                      onClick={clearAllCompletedScans}
                    >
                      <Trash2 className="h-3 w-3 mr-1" />
                      Clear All
                    </Button>
                  )}
                </div>
              </DropdownMenuLabel>
              <DropdownMenuSeparator />
              
              {runningScans.length > 0 && (
                <>
                  <DropdownMenuLabel className="text-xs text-muted-foreground flex items-center gap-2">
                    <Play className="h-3 w-3 text-blue-500" />
                    Running Scans ({runningScans.length})
                  </DropdownMenuLabel>
                  {runningScans.map((scan) => (
                    <DropdownMenuItem key={scan.scanId} className="flex flex-col items-start gap-2 p-3 rounded-lg">
                      <div className="flex items-center justify-between w-full">
                        <div className="flex items-center gap-2">
                          <Play className="h-3 w-3 text-blue-500 animate-pulse" />
                          <span className="text-sm font-medium">{getScanTypeLabel(scan.scanType)}</span>
                        </div>
                        <span className="text-xs text-muted-foreground">{formatTime(scan.startTime)}</span>
                      </div>
                      <div className="w-full">
                        <p className="text-xs text-muted-foreground mb-1">{scan.target}</p>
                        <Progress value={scan.progress} className="h-1" />
                        <p className="text-xs text-muted-foreground mt-1">{scan.progress}% complete</p>
                      </div>
                    </DropdownMenuItem>
                  ))}
                  <DropdownMenuSeparator />
                </>
              )}

              {completedScans.length > 0 && (
                <>
                  <DropdownMenuLabel className="text-xs text-muted-foreground flex items-center gap-2">
                    <CheckCircle className="h-3 w-3 text-green-500" />
                    Completed Scans ({completedScans.length})
                  </DropdownMenuLabel>
                  {completedScans.map((scan) => (
                    <DropdownMenuItem key={scan.scanId} className="flex flex-col items-start gap-2 p-3 rounded-lg">
                      <div className="flex items-center justify-between w-full">
                        <div className="flex items-center gap-2">
                          <CheckCircle className="h-3 w-3 text-green-500" />
                          <span className="text-sm font-medium">{getScanTypeLabel(scan.scanType)}</span>
                        </div>
                        <div className="flex items-center gap-1">
                          <span className="text-xs text-muted-foreground">{formatTime(scan.startTime)}</span>
                          <Button
                            variant="ghost"
                            size="sm"
                            className="h-4 w-4 p-0 text-muted-foreground hover:text-foreground"
                            onClick={(e) => {
                              e.stopPropagation()
                              removeScan(scan.scanId)
                            }}
                          >
                            <X className="h-3 w-3" />
                          </Button>
                        </div>
                      </div>
                      <p className="text-xs text-muted-foreground">{scan.target}</p>
                      <div className="flex gap-1">
                        <Link href="/dashboard/reconnaissance">
                          <Button variant="outline" size="sm" className="h-6 text-xs rounded-xl border border-border hover:bg-accent">
                            <Eye className="h-3 w-3 mr-1" />
                            View Results
                          </Button>
                        </Link>
                      </div>
                    </DropdownMenuItem>
                  ))}
                </>
              )}

              {notifications === 0 && (
                <DropdownMenuItem disabled className="text-center text-muted-foreground">
                  No active or completed scans
                </DropdownMenuItem>
              )}
            </DropdownMenuContent>
          </DropdownMenu>

          <div className="hidden sm:flex items-center space-x-2 px-3 py-1 bg-secondary rounded-xl border border-border">
            <User className="h-4 w-4 text-muted-foreground" />
            <span className="text-sm text-foreground">Security Analyst</span>
          </div>

          <div className="sm:hidden">
            <Button variant="ghost" size="icon" className="text-muted-foreground hover:text-foreground hover:bg-accent h-8 w-8">
              <User className="h-3 w-3" />
            </Button>
          </div>
        </div>
      </div>
    </header>
  )
}
