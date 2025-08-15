"use client"

import { useState, useEffect } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Badge } from "@/components/ui/badge"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Search, Download, Activity, User, Shield, AlertTriangle, RefreshCw, Calendar, Filter, Trash2 } from "lucide-react"

interface AuditLog {
  id: number
  timestamp: string
  user: string
  action: string
  target: string
  module: string
  status: string
  severity: string
  ip: string
  details: string
  user_agent?: string
  metadata?: any
}

interface AuditStatistics {
  total_actions: number
  failed_actions: number
  active_users: number
  security_events: number
}

interface PaginationInfo {
  current_page: number
  total_pages: number
  total_count: number
  has_next: boolean
  has_previous: boolean
}

interface FilterOptions {
  available_modules: string[]
  available_statuses: string[]
  available_severities: string[]
  available_users: string[]
}

export default function AuditLogsPage() {
  const [auditLogs, setAuditLogs] = useState<AuditLog[]>([])
  const [statistics, setStatistics] = useState<AuditStatistics>({
    total_actions: 0,
    failed_actions: 0,
    active_users: 0,
    security_events: 0
  })
  const [pagination, setPagination] = useState<PaginationInfo>({
    current_page: 1,
    total_pages: 1,
    total_count: 0,
    has_next: false,
    has_previous: false
  })
  const [filterOptions, setFilterOptions] = useState<FilterOptions>({
    available_modules: ['scanning', 'reconnaissance', 'exploitation', 'reporting', 'administration', 'authentication', 'user_management', 'system'],
    available_statuses: ['success', 'failed', 'warning', 'info'],
    available_severities: ['low', 'medium', 'high', 'critical'],
    available_users: []
  })
  
  // Filter states
  const [searchTerm, setSearchTerm] = useState("")
  const [filterModule, setFilterModule] = useState("all")
  const [filterStatus, setFilterStatus] = useState("all")
  const [filterUser, setFilterUser] = useState("all")
  const [filterSeverity, setFilterSeverity] = useState("all")
  const [startDate, setStartDate] = useState("")
  const [endDate, setEndDate] = useState("")
  
  // UI states
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState("")
  const [exporting, setExporting] = useState(false)
  const [clearing, setClearing] = useState(false)

  // Fetch audit logs
  const fetchAuditLogs = async (page = 1) => {
    try {
      setLoading(true)
      setError("")
      
      const params = new URLSearchParams({
        page: page.toString(),
        page_size: "50"
      })
      
      if (searchTerm) params.append("search", searchTerm)
      if (filterModule && filterModule !== "all") params.append("module", filterModule)
      if (filterStatus && filterStatus !== "all") params.append("status", filterStatus)
      if (filterUser && filterUser !== "all") params.append("user", filterUser)
      if (filterSeverity && filterSeverity !== "all") params.append("severity", filterSeverity)
      if (startDate) params.append("start_date", startDate)
      if (endDate) params.append("end_date", endDate)
      
      const response = await fetch(`/api/audit-logs?${params}`)
      const data = await response.json()
      
      if (data.success) {
        setAuditLogs(data.logs)
        setStatistics(data.statistics)
        setPagination(data.pagination)
        setFilterOptions(data.filters)
      } else {
        setError(data.error || "Failed to fetch audit logs")
      }
    } catch (error) {
      console.error("Error fetching audit logs:", error)
      setError("Failed to fetch audit logs")
    } finally {
      setLoading(false)
    }
  }

  // Fetch statistics
  const fetchStatistics = async () => {
    try {
      const response = await fetch("/api/audit-logs/statistics")
      const data = await response.json()
      
      if (data.success) {
        setStatistics(data.statistics)
      }
    } catch (error) {
      console.error("Error fetching statistics:", error)
    }
  }

  // Export logs
  const exportLogs = async (format: 'json' | 'csv' = 'json') => {
    try {
      setExporting(true)
      
      const response = await fetch("/api/audit-logs", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          action: "export",
          format: format,
          filters: {
            search: searchTerm,
            module: filterModule !== "all" ? filterModule : undefined,
            status: filterStatus !== "all" ? filterStatus : undefined,
            start_date: startDate,
            end_date: endDate
          }
        }),
      })
      
      if (format === 'csv') {
        const blob = await response.blob()
        const url = window.URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = 'audit_logs.csv'
        document.body.appendChild(a)
        a.click()
        window.URL.revokeObjectURL(url)
        document.body.removeChild(a)
      } else {
        const data = await response.json()
        if (data.success) {
          const blob = new Blob([JSON.stringify(data.data, null, 2)], { type: 'application/json' })
          const url = window.URL.createObjectURL(blob)
          const a = document.createElement('a')
          a.href = url
          a.download = 'audit_logs.json'
          document.body.appendChild(a)
          a.click()
          window.URL.revokeObjectURL(url)
          document.body.removeChild(a)
        }
      }
    } catch (error) {
      console.error("Error exporting logs:", error)
      setError("Failed to export logs")
    } finally {
      setExporting(false)
    }
  }

  // Clear old logs
  const clearOldLogs = async () => {
    if (!confirm("Are you sure you want to clear old audit logs? This action cannot be undone.")) {
      return
    }
    
    try {
      setClearing(true)
      
      const response = await fetch("/api/audit-logs", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          action: "clear",
          days_to_keep: 90
        }),
      })
      
      const data = await response.json()
      
      if (data.success) {
        alert(`Successfully cleared ${data.deleted_count} old log entries`)
        fetchAuditLogs(1)
      } else {
        setError(data.error || "Failed to clear logs")
      }
    } catch (error) {
      console.error("Error clearing logs:", error)
      setError("Failed to clear logs")
    } finally {
      setClearing(false)
    }
  }

  // Apply filters
  const applyFilters = () => {
    fetchAuditLogs(1)
  }

  // Clear filters
  const clearFilters = () => {
    setSearchTerm("")
    setFilterModule("all")
    setFilterStatus("all")
    setFilterUser("all")
    setFilterSeverity("all")
    setStartDate("")
    setEndDate("")
    fetchAuditLogs(1)
  }

  // Load data on component mount
  useEffect(() => {
    fetchAuditLogs()
  }, [])

  const getStatusColor = (status: string) => {
    switch (status) {
      case "success":
        return "bg-green-600"
      case "failed":
        return "bg-red-600"
      case "warning":
        return "bg-yellow-600"
      case "info":
        return "bg-blue-600"
      default:
        return "bg-gray-600"
    }
  }

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "critical":
        return "bg-red-800"
      case "high":
        return "bg-red-600"
      case "medium":
        return "bg-yellow-600"
      case "low":
        return "bg-green-600"
      default:
        return "bg-gray-600"
    }
  }

  const getActionIcon = (module: string) => {
    switch (module) {
      case "scanning":
        return <Shield className="h-4 w-4" />
      case "reconnaissance":
        return <Search className="h-4 w-4" />
      case "exploitation":
        return <AlertTriangle className="h-4 w-4" />
      case "reporting":
        return <Download className="h-4 w-4" />
      case "administration":
      case "user_management":
        return <User className="h-4 w-4" />
      case "authentication":
        return <Shield className="h-4 w-4" />
      default:
        return <Activity className="h-4 w-4" />
    }
  }

  return (
    <div className="space-y-4 sm:space-y-6">
      <div className="flex justify-between items-start">
        <div>
          <h1 className="text-2xl sm:text-3xl font-bold text-foreground mb-2">Audit Logs</h1>
          <p className="text-muted-foreground text-sm sm:text-base">Monitor and track all system activities and user actions</p>
        </div>
        <div className="flex gap-2">
          <Button 
            variant="outline" 
            size="sm" 
            onClick={() => fetchAuditLogs(pagination.current_page)}
            disabled={loading}
          >
            <RefreshCw className={`h-4 w-4 mr-2 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </Button>
        </div>
      </div>

      {error && (
        <Alert className="border-red-200 bg-red-50">
          <AlertTriangle className="h-4 w-4" />
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      {/* Filters */}
      <Card className="bg-card border-border">
        <CardHeader>
          <CardTitle className="text-foreground text-lg sm:text-xl flex items-center gap-2">
            <Filter className="h-5 w-5" />
            Filter & Search
          </CardTitle>
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
              <Select value={filterModule} onValueChange={setFilterModule}>
                <SelectTrigger className="bg-secondary border-border text-foreground text-sm sm:text-base">
                  <SelectValue placeholder="All Modules" />
                </SelectTrigger>
                <SelectContent className="bg-secondary border-border">
                  <SelectItem value="all">All Modules</SelectItem>
                  {filterOptions.available_modules.filter(module => module && module.trim() !== '').map((module) => (
                    <SelectItem key={module} value={module}>{module}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-2">
              <label className="text-foreground text-sm">Status</label>
              <Select value={filterStatus} onValueChange={setFilterStatus}>
                <SelectTrigger className="bg-secondary border-border text-foreground text-sm sm:text-base">
                  <SelectValue placeholder="All Statuses" />
                </SelectTrigger>
                <SelectContent className="bg-secondary border-border">
                  <SelectItem value="all">All Statuses</SelectItem>
                  {filterOptions.available_statuses.filter(status => status && status.trim() !== '').map((status) => (
                    <SelectItem key={status} value={status}>{status}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-2">
              <label className="text-foreground text-sm">Severity</label>
              <Select value={filterSeverity} onValueChange={setFilterSeverity}>
                <SelectTrigger className="bg-secondary border-border text-foreground text-sm sm:text-base">
                  <SelectValue placeholder="All Severities" />
                </SelectTrigger>
                <SelectContent className="bg-secondary border-border">
                  <SelectItem value="all">All Severities</SelectItem>
                  {filterOptions.available_severities.filter(severity => severity && severity.trim() !== '').map((severity) => (
                    <SelectItem key={severity} value={severity}>{severity}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-2">
              <label className="text-foreground text-sm">User</label>
              <Select value={filterUser} onValueChange={setFilterUser}>
                <SelectTrigger className="bg-secondary border-border text-foreground text-sm sm:text-base">
                  <SelectValue placeholder="All Users" />
                </SelectTrigger>
                <SelectContent className="bg-secondary border-border">
                  <SelectItem value="all">All Users</SelectItem>
                  {filterOptions.available_users.filter(user => user && user.trim() !== '').map((user) => (
                    <SelectItem key={user} value={user}>{user}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-2">
              <label className="text-foreground text-sm">Start Date</label>
              <Input
                type="date"
                value={startDate}
                onChange={(e) => setStartDate(e.target.value)}
                className="bg-secondary border-border text-foreground text-sm sm:text-base"
              />
            </div>

            <div className="space-y-2">
              <label className="text-foreground text-sm">End Date</label>
              <Input
                type="date"
                value={endDate}
                onChange={(e) => setEndDate(e.target.value)}
                className="bg-secondary border-border text-foreground text-sm sm:text-base"
              />
            </div>

            <div className="space-y-2">
              <label className="text-foreground text-sm">Actions</label>
              <div className="flex gap-2">
                <Button 
                  onClick={applyFilters}
                  disabled={loading}
                  className="flex-1 bg-blue-600 hover:bg-blue-700 text-sm sm:text-base"
                >
                  Apply
                </Button>
                <Button 
                  variant="outline"
                  onClick={clearFilters}
                  disabled={loading}
                  className="flex-1 text-sm sm:text-base"
                >
                  Clear
                </Button>
              </div>
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
                <p className="text-xl sm:text-2xl font-bold text-foreground">{statistics.total_actions}</p>
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
                <p className="text-xl sm:text-2xl font-bold text-foreground">{statistics.failed_actions}</p>
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
                <p className="text-xl sm:text-2xl font-bold text-foreground">{statistics.active_users}</p>
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
                <p className="text-xl sm:text-2xl font-bold text-foreground">{statistics.security_events}</p>
              </div>
              <Shield className="h-6 w-6 sm:h-8 sm:w-8 text-purple-400" />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Export and Clear Actions */}
      <div className="flex gap-2 justify-end">
        <Button 
          variant="outline"
          onClick={() => exportLogs('json')}
          disabled={exporting || auditLogs.length === 0}
          className="text-sm"
        >
          <Download className="h-4 w-4 mr-2" />
          Export JSON
        </Button>
        <Button 
          variant="outline"
          onClick={() => exportLogs('csv')}
          disabled={exporting || auditLogs.length === 0}
          className="text-sm"
        >
          <Download className="h-4 w-4 mr-2" />
          Export CSV
        </Button>
        <Button 
          variant="outline"
          onClick={clearOldLogs}
          disabled={clearing}
          className="text-sm text-red-600 hover:text-red-700"
        >
          <Trash2 className="h-4 w-4 mr-2" />
          Clear Old Logs
        </Button>
      </div>

      {/* Audit Logs Table */}
      <Card className="bg-card border-border">
        <CardHeader>
          <CardTitle className="text-foreground text-lg sm:text-xl">Activity Log</CardTitle>
          <CardDescription className="text-muted-foreground text-sm">
            {loading ? "Loading..." : `Showing ${auditLogs.length} of ${pagination.total_count} log entries`}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="flex items-center justify-center py-8">
              <RefreshCw className="h-8 w-8 animate-spin text-muted-foreground" />
              <span className="ml-2 text-muted-foreground">Loading audit logs...</span>
            </div>
          ) : auditLogs.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground">
              No audit logs found
            </div>
          ) : (
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
                      <TableHead className="text-foreground text-xs sm:text-sm whitespace-nowrap">Severity</TableHead>
                      <TableHead className="text-foreground text-xs sm:text-sm whitespace-nowrap">IP Address</TableHead>
                      <TableHead className="text-foreground text-xs sm:text-sm whitespace-nowrap">Details</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {auditLogs.map((log) => (
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
                        <TableCell>
                          <Badge className={`${getSeverityColor(log.severity)} text-xs`}>{log.severity}</Badge>
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
          )}
          
          {/* Pagination */}
          {pagination.total_pages > 1 && (
            <div className="flex items-center justify-between mt-4">
              <div className="text-sm text-muted-foreground">
                Page {pagination.current_page} of {pagination.total_pages}
              </div>
              <div className="flex gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => fetchAuditLogs(pagination.current_page - 1)}
                  disabled={!pagination.has_previous || loading}
                >
                  Previous
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => fetchAuditLogs(pagination.current_page + 1)}
                  disabled={!pagination.has_next || loading}
                >
                  Next
                </Button>
              </div>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
