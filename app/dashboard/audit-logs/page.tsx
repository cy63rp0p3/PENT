"use client"

import { useState } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Badge } from "@/components/ui/badge"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Search, Download, Activity, User, Shield, AlertTriangle } from "lucide-react"

export default function AuditLogsPage() {
  const [searchTerm, setSearchTerm] = useState("")
  const [filterType, setFilterType] = useState("all")
  const [filterUser, setFilterUser] = useState("all")

  const auditLogs = [
    {
      id: 1,
      timestamp: "2024-01-15 14:30:25",
      user: "john.doe@company.com",
      action: "Port Scan Initiated",
      target: "192.168.1.0/24",
      module: "Scanning",
      status: "success",
      ip: "10.0.0.15",
      details: "Nmap TCP SYN scan on 1000 ports",
    },
    {
      id: 2,
      timestamp: "2024-01-15 14:25:12",
      user: "jane.smith@company.com",
      action: "Vulnerability Scan Completed",
      target: "web.example.com",
      module: "Scanning",
      status: "success",
      ip: "10.0.0.22",
      details: "15 vulnerabilities found, 3 critical",
    },
    {
      id: 3,
      timestamp: "2024-01-15 14:20:08",
      user: "admin@company.com",
      action: "User Role Modified",
      target: "mike.johnson@company.com",
      module: "Administration",
      status: "success",
      ip: "10.0.0.1",
      details: "Role changed from Viewer to Pentester",
    },
    {
      id: 4,
      timestamp: "2024-01-15 14:15:33",
      user: "sarah.wilson@company.com",
      action: "Report Generated",
      target: "Security Assessment #001",
      module: "Reporting",
      status: "success",
      ip: "10.0.0.18",
      details: "PDF report generated successfully",
    },
    {
      id: 5,
      timestamp: "2024-01-15 14:10:45",
      user: "unknown@external.com",
      action: "Failed Login Attempt",
      target: "Authentication System",
      module: "Authentication",
      status: "failed",
      ip: "203.0.113.45",
      details: "Invalid credentials provided",
    },
    {
      id: 6,
      timestamp: "2024-01-15 14:05:19",
      user: "john.doe@company.com",
      action: "Subdomain Enumeration",
      target: "example.com",
      module: "Reconnaissance",
      status: "success",
      ip: "10.0.0.15",
      details: "25 subdomains discovered",
    },
    {
      id: 7,
      timestamp: "2024-01-15 14:00:02",
      user: "admin@company.com",
      action: "System Configuration Changed",
      target: "Scan Rate Limits",
      module: "Administration",
      status: "success",
      ip: "10.0.0.1",
      details: "Max concurrent scans increased to 10",
    },
    {
      id: 8,
      timestamp: "2024-01-15 13:55:17",
      user: "jane.smith@company.com",
      action: "Exploit Module Accessed",
      target: "MS17-010 EternalBlue",
      module: "Exploitation",
      status: "warning",
      ip: "10.0.0.22",
      details: "Exploit module loaded for testing",
    },
  ]

  const getStatusColor = (status: string) => {
    switch (status) {
      case "success":
        return "bg-green-600"
      case "failed":
        return "bg-red-600"
      case "warning":
        return "bg-yellow-600"
      default:
        return "bg-gray-600"
    }
  }

  const getActionIcon = (module: string) => {
    switch (module) {
      case "Scanning":
        return <Shield className="h-4 w-4" />
      case "Reconnaissance":
        return <Search className="h-4 w-4" />
      case "Exploitation":
        return <AlertTriangle className="h-4 w-4" />
      case "Reporting":
        return <Download className="h-4 w-4" />
      case "Administration":
        return <User className="h-4 w-4" />
      case "Authentication":
        return <Shield className="h-4 w-4" />
      default:
        return <Activity className="h-4 w-4" />
    }
  }

  const filteredLogs = auditLogs.filter((log) => {
    const matchesSearch =
      log.action.toLowerCase().includes(searchTerm.toLowerCase()) ||
      log.user.toLowerCase().includes(searchTerm.toLowerCase()) ||
      log.target.toLowerCase().includes(searchTerm.toLowerCase())
    const matchesType = filterType === "all" || log.module.toLowerCase() === filterType.toLowerCase()
    const matchesUser = filterUser === "all" || log.user === filterUser

    return matchesSearch && matchesType && matchesUser
  })

  return (
    <div className="space-y-4 sm:space-y-6">
      <div>
        <h1 className="text-2xl sm:text-3xl font-bold text-foreground mb-2">Audit Logs</h1>
        <p className="text-muted-foreground text-sm sm:text-base">Monitor and track all system activities and user actions</p>
      </div>

      {/* Filters */}
      <Card className="bg-card border-border">
        <CardHeader>
          <CardTitle className="text-foreground text-lg sm:text-xl">Filter & Search</CardTitle>
          <CardDescription className="text-muted-foreground text-sm">Filter audit logs by various criteria</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 sm:gap-4">
            <div className="space-y-2">
              <label className="text-foreground text-sm">Search</label>
              <div className="relative">
                <Search className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
                <Input
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  placeholder="Search logs..."
                  className="pl-10 bg-secondary border-border text-foreground text-sm sm:text-base"
                />
              </div>
            </div>

            <div className="space-y-2">
              <label className="text-foreground text-sm">Module</label>
              <Select value={filterType} onValueChange={setFilterType}>
                <SelectTrigger className="bg-secondary border-border text-foreground text-sm sm:text-base">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent className="bg-secondary border-border">
                  <SelectItem value="all">All Modules</SelectItem>
                  <SelectItem value="scanning">Scanning</SelectItem>
                  <SelectItem value="reconnaissance">Reconnaissance</SelectItem>
                  <SelectItem value="exploitation">Exploitation</SelectItem>
                  <SelectItem value="reporting">Reporting</SelectItem>
                  <SelectItem value="administration">Administration</SelectItem>
                  <SelectItem value="authentication">Authentication</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-2">
              <label className="text-foreground text-sm">User</label>
              <Select value={filterUser} onValueChange={setFilterUser}>
                <SelectTrigger className="bg-secondary border-border text-foreground text-sm sm:text-base">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent className="bg-secondary border-border">
                  <SelectItem value="all">All Users</SelectItem>
                  <SelectItem value="john.doe@company.com">John Doe</SelectItem>
                  <SelectItem value="jane.smith@company.com">Jane Smith</SelectItem>
                  <SelectItem value="admin@company.com">Admin</SelectItem>
                  <SelectItem value="sarah.wilson@company.com">Sarah Wilson</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-2">
              <label className="text-foreground text-sm">Actions</label>
              <Button className="w-full bg-blue-600 hover:bg-blue-700 text-sm sm:text-base">
                <Download className="h-4 w-4 mr-2" />
                <span className="hidden sm:inline">Export Logs</span>
                <span className="sm:hidden">Export</span>
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Statistics */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 sm:gap-6">
        <Card className="bg-card border-border">
          <CardContent className="p-4 sm:p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-muted-foreground text-xs sm:text-sm">Total Actions</p>
                <p className="text-xl sm:text-2xl font-bold text-foreground">{auditLogs.length}</p>
              </div>
              <Activity className="h-6 w-6 sm:h-8 sm:w-8 text-blue-400" />
            </div>
          </CardContent>
        </Card>
        <Card className="bg-card border-border">
          <CardContent className="p-4 sm:p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-muted-foreground text-xs sm:text-sm">Failed Actions</p>
                <p className="text-xl sm:text-2xl font-bold text-foreground">
                  {auditLogs.filter((log) => log.status === "failed").length}
                </p>
              </div>
              <AlertTriangle className="h-6 w-6 sm:h-8 sm:w-8 text-red-400" />
            </div>
          </CardContent>
        </Card>
        <Card className="bg-card border-border">
          <CardContent className="p-4 sm:p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-muted-foreground text-xs sm:text-sm">Active Users</p>
                <p className="text-xl sm:text-2xl font-bold text-foreground">
                  {new Set(auditLogs.map((log) => log.user)).size}
                </p>
              </div>
              <User className="h-6 w-6 sm:h-8 sm:w-8 text-green-400" />
            </div>
          </CardContent>
        </Card>
        <Card className="bg-card border-border">
          <CardContent className="p-4 sm:p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-muted-foreground text-xs sm:text-sm">Security Events</p>
                <p className="text-xl sm:text-2xl font-bold text-foreground">
                  {auditLogs.filter((log) => log.module === "Authentication" || log.status === "failed").length}
                </p>
              </div>
              <Shield className="h-6 w-6 sm:h-8 sm:w-8 text-purple-400" />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Audit Logs Table */}
      <Card className="bg-card border-border">
        <CardHeader>
          <CardTitle className="text-foreground text-lg sm:text-xl">Activity Log</CardTitle>
          <CardDescription className="text-muted-foreground text-sm">
            Showing {filteredLogs.length} of {auditLogs.length} log entries
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="overflow-x-auto -mx-4 sm:mx-0">
            <div className="min-w-full inline-block align-middle">
              <Table>
                <TableHeader>
                  <TableRow className="border-border">
                    <TableHead className="text-foreground text-xs sm:text-sm whitespace-nowrap">Timestamp</TableHead>
                    <TableHead className="text-foreground text-xs sm:text-sm whitespace-nowrap">User</TableHead>
                    <TableHead className="text-foreground text-xs sm:text-sm whitespace-nowrap">Action</TableHead>
                    <TableHead className="text-foreground text-xs sm:text-sm whitespace-nowrap">Target</TableHead>
                    <TableHead className="text-foreground text-xs sm:text-sm whitespace-nowrap">Module</TableHead>
                    <TableHead className="text-foreground text-xs sm:text-sm whitespace-nowrap">Status</TableHead>
                    <TableHead className="text-foreground text-xs sm:text-sm whitespace-nowrap">IP Address</TableHead>
                    <TableHead className="text-foreground text-xs sm:text-sm whitespace-nowrap">Details</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredLogs.map((log) => (
                    <TableRow key={log.id} className="border-border hover:bg-muted">
                      <TableCell className="text-foreground font-mono text-xs sm:text-sm whitespace-nowrap">
                        {log.timestamp}
                      </TableCell>
                      <TableCell className="text-foreground min-w-0">
                        <div className="flex items-center space-x-2">
                          <User className="h-3 w-3 sm:h-4 sm:w-4 text-muted-foreground flex-shrink-0" />
                          <span className="text-xs sm:text-sm truncate max-w-[120px] sm:max-w-none">{log.user}</span>
                        </div>
                      </TableCell>
                      <TableCell className="text-foreground min-w-0">
                        <div className="flex items-center space-x-2">
                          {getActionIcon(log.module)}
                          <span className="text-xs sm:text-sm truncate max-w-[100px] sm:max-w-none">{log.action}</span>
                        </div>
                      </TableCell>
                      <TableCell className="text-foreground text-xs sm:text-sm max-w-[100px] sm:max-w-xs truncate">
                        {log.target}
                      </TableCell>
                      <TableCell className="text-foreground">
                        <Badge variant="outline" className="border-border text-foreground text-xs">
                          {log.module}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <Badge className={`${getStatusColor(log.status)} text-xs`}>{log.status}</Badge>
                      </TableCell>
                      <TableCell className="text-foreground font-mono text-xs sm:text-sm whitespace-nowrap">
                        {log.ip}
                      </TableCell>
                      <TableCell className="text-muted-foreground text-xs sm:text-sm max-w-[150px] sm:max-w-xs truncate">
                        {log.details}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
