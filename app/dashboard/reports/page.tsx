"use client"

import { useState, useEffect } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Badge } from "@/components/ui/badge"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Checkbox } from "@/components/ui/checkbox"
import { 
  FileText, 
  Download, 
  Eye, 
  Calendar, 
  Target, 
  AlertTriangle, 
  CheckCircle, 
  Info, 
  Globe, 
  Network, 
  Search,
  Activity,
  Server,
  Database,
  Lock,
  Unlock,
  AlertCircle,
  XCircle,
  Zap,
  Trash2,
  Plus,
  FileDown,
  CheckSquare,
  Square,
  X,
  RefreshCw
} from "lucide-react"

interface IndividualReport {
  id: string
  title: string
  scan_type: string
  target: string
  timestamp: string
  status: string
  severity: string
  summary: string
  details: any
  findings_count: number
}

interface ComprehensiveReport {
  id: string
  title: string
  generated_at: string
  included_reports: string[]
  total_findings: number
  overall_severity: string
  status: 'draft' | 'generated' | 'downloaded'
}

const renderScanResults = (details: any, scanType: string) => {
  if (!details) return <p className="text-sm text-muted-foreground">No detailed results available</p>

  switch (scanType) {
    case 'port_scan':
    case 'basic_port_scan':
      return (
        <div className="space-y-4">
          {/* Port Scan Summary */}
          {details.summary && (
            <div className="bg-secondary/30 p-4 rounded-lg border border-border">
              <h4 className="font-medium text-sm mb-2 text-card-foreground">Port Scan Summary</h4>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                <div>
                  <span className="text-muted-foreground">Total Ports:</span>
                  <span className="ml-2 font-medium text-card-foreground">{details.summary.total_ports}</span>
                </div>
                <div>
                  <span className="text-muted-foreground">Open:</span>
                  <span className="ml-2 font-medium text-green-500">{details.summary.open_count}</span>
                </div>
                <div>
                  <span className="text-muted-foreground">Closed:</span>
                  <span className="ml-2 font-medium text-red-500">{details.summary.closed_count}</span>
                </div>
                <div>
                  <span className="text-muted-foreground">Filtered:</span>
                  <span className="ml-2 font-medium text-yellow-500">{details.summary.filtered_count}</span>
                </div>
              </div>
            </div>
          )}

          {/* Open Ports */}
          {details.open_ports && details.open_ports.length > 0 && (
            <div className="bg-green-50 dark:bg-green-900/20 p-4 rounded-lg border border-green-200 dark:border-green-800">
              <h4 className="font-medium text-sm mb-3 flex items-center gap-2 text-black dark:text-white">
                <CheckCircle className="h-4 w-4 text-green-500" />
                Open Ports ({details.open_ports.length})
              </h4>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2">
                {details.open_ports.map((port: any, index: number) => (
                  <div key={index} className="bg-white dark:bg-green-900/30 p-2 rounded border border-border">
                    <div className="flex items-center justify-between">
                      <span className="font-medium text-sm text-black dark:text-white">Port {port.port}</span>
                      <Badge variant="outline" className="text-xs bg-background text-foreground border-border">
                        {port.service}
                      </Badge>
                    </div>
                    {port.response_time && port.response_time > 0 && (
                      <p className="text-xs text-muted-foreground mt-1">
                        Response: {port.response_time}ms
                      </p>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Closed Ports */}
          {details.closed_ports && details.closed_ports.length > 0 && (
            <div className="bg-red-50 dark:bg-red-900/20 p-4 rounded-lg border border-red-200 dark:border-red-800">
              <h4 className="font-medium text-sm mb-3 flex items-center gap-2 text-black dark:text-white">
                <XCircle className="h-4 w-4 text-red-500" />
                Closed Ports ({details.closed_ports.length})
              </h4>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2">
                {details.closed_ports.slice(0, 20).map((port: any, index: number) => (
                  <div key={index} className="bg-white dark:bg-red-900/30 p-2 rounded border border-border">
                    <div className="flex items-center justify-between">
                      <span className="font-medium text-sm text-black dark:text-white">Port {port.port}</span>
                      <Badge variant="outline" className="text-xs bg-background text-foreground border-border">
                        {port.service}
                      </Badge>
                    </div>
                  </div>
                ))}
                {details.closed_ports.length > 20 && (
                  <div className="col-span-full text-center text-sm text-muted-foreground">
                    ... and {details.closed_ports.length - 20} more closed ports
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Filtered Ports */}
          {details.filtered_ports && details.filtered_ports.length > 0 && (
            <div className="bg-yellow-50 dark:bg-yellow-900/20 p-4 rounded-lg border border-yellow-200 dark:border-yellow-800">
              <h4 className="font-medium text-sm mb-3 flex items-center gap-2 text-black dark:text-white">
                <AlertTriangle className="h-4 w-4 text-yellow-500" />
                Filtered Ports ({details.filtered_ports.length})
              </h4>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2">
                {details.filtered_ports.slice(0, 20).map((port: any, index: number) => (
                  <div key={index} className="bg-white dark:bg-yellow-900/30 p-2 rounded border border-border">
                    <div className="flex items-center justify-between">
                      <span className="font-medium text-sm text-black dark:text-white">Port {port.port}</span>
                      <Badge variant="outline" className="text-xs bg-background text-foreground border-border">
                        {port.service}
                      </Badge>
                    </div>
                  </div>
                ))}
                {details.filtered_ports.length > 20 && (
                  <div className="col-span-full text-center text-sm text-muted-foreground">
                    ... and {details.filtered_ports.length - 20} more filtered ports
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      )

    case 'vulnerability_scan':
      return (
        <div className="space-y-4">
          {/* Vulnerability Summary */}
          {details.summary && (
            <div className="bg-secondary/30 p-4 rounded-lg border border-border">
              <h4 className="font-medium text-sm mb-2 text-card-foreground">Vulnerability Summary</h4>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                <div>
                  <span className="text-muted-foreground">Critical:</span>
                  <span className="ml-2 font-medium text-red-500">{details.summary.critical_vulnerabilities || 0}</span>
                </div>
                <div>
                  <span className="text-muted-foreground">High:</span>
                  <span className="ml-2 font-medium text-orange-500">{details.summary.high_vulnerabilities || 0}</span>
                </div>
                <div>
                  <span className="text-muted-foreground">Medium:</span>
                  <span className="ml-2 font-medium text-yellow-500">{details.summary.medium_vulnerabilities || 0}</span>
                </div>
                <div>
                  <span className="text-muted-foreground">Low:</span>
                  <span className="ml-2 font-medium text-blue-500">{details.summary.low_vulnerabilities || 0}</span>
                </div>
              </div>
            </div>
          )}

          {/* Critical Vulnerabilities */}
          {details.critical_vulnerabilities && details.critical_vulnerabilities.length > 0 && (
            <div className="bg-red-50 dark:bg-red-900/20 p-4 rounded-lg border border-red-200 dark:border-red-800">
              <h4 className="font-medium text-sm mb-3 flex items-center gap-2 text-card-foreground">
                <AlertTriangle className="h-4 w-4 text-red-500" />
                Critical Vulnerabilities ({details.critical_vulnerabilities.length})
              </h4>
              <div className="space-y-3">
                {details.critical_vulnerabilities.map((vuln: any, index: number) => (
                  <div key={index} className="bg-white dark:bg-red-900/30 p-3 rounded border border-border">
                    <h5 className="font-medium text-sm mb-1 text-card-foreground">{vuln.name || `Vulnerability ${index + 1}`}</h5>
                    <p className="text-xs text-muted-foreground mb-2">{vuln.description || 'No description available'}</p>
                    {vuln.cwe && (
                      <Badge variant="outline" className="text-xs mr-2">CWE: {vuln.cwe}</Badge>
                    )}
                    {vuln.cvss && (
                      <Badge variant="outline" className="text-xs">CVSS: {vuln.cvss}</Badge>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* High Vulnerabilities */}
          {details.high_vulnerabilities && details.high_vulnerabilities.length > 0 && (
            <div className="bg-orange-50 dark:bg-orange-900/20 p-4 rounded-lg border border-orange-200 dark:border-orange-800">
              <h4 className="font-medium text-sm mb-3 flex items-center gap-2 text-card-foreground">
                <AlertTriangle className="h-4 w-4 text-orange-500" />
                High Vulnerabilities ({details.high_vulnerabilities.length})
              </h4>
              <div className="space-y-3">
                {details.high_vulnerabilities.slice(0, 10).map((vuln: any, index: number) => (
                  <div key={index} className="bg-white dark:bg-orange-900/30 p-3 rounded border border-border">
                    <h5 className="font-medium text-sm mb-1 text-card-foreground">{vuln.name || `Vulnerability ${index + 1}`}</h5>
                    <p className="text-xs text-muted-foreground mb-2">{vuln.description || 'No description available'}</p>
                    {vuln.cwe && (
                      <Badge variant="outline" className="text-xs mr-2">CWE: {vuln.cwe}</Badge>
                    )}
                    {vuln.cvss && (
                      <Badge variant="outline" className="text-xs">CVSS: {vuln.cvss}</Badge>
                    )}
                  </div>
                ))}
                {details.high_vulnerabilities.length > 10 && (
                  <div className="text-center text-sm text-muted-foreground">
                    ... and {details.high_vulnerabilities.length - 10} more high vulnerabilities
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      )

    case 'whois':
      return (
        <div className="bg-secondary/30 p-4 rounded-lg border border-border">
          <h4 className="font-medium text-sm mb-3 text-card-foreground">WHOIS Information</h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
            {Object.entries(details).map(([key, value]) => (
              <div key={key}>
                <span className="text-muted-foreground capitalize">{key.replace(/_/g, ' ')}:</span>
                <span className="ml-2 font-medium text-card-foreground">{String(value)}</span>
              </div>
            ))}
          </div>
        </div>
      )

    case 'dns':
      return (
        <div className="space-y-4">
          {Object.entries(details).map(([recordType, records]) => (
            <div key={recordType} className="bg-secondary/30 p-4 rounded-lg border border-border">
              <h4 className="font-medium text-sm mb-3 capitalize text-card-foreground">{recordType.replace(/_/g, ' ')} Records</h4>
              <div className="space-y-2">
                {Array.isArray(records) && records.map((record: any, index: number) => (
                  <div key={index} className="bg-white dark:bg-secondary p-2 rounded border border-border">
                    <span className="text-sm font-medium text-card-foreground">{record}</span>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      )

    case 'subdomain':
      return (
        <div className="bg-secondary/30 p-4 rounded-lg border border-border">
          <h4 className="font-medium text-sm mb-3 text-card-foreground">Discovered Subdomains</h4>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2">
            {details.subdomains && details.subdomains.map((subdomain: string, index: number) => (
              <div key={index} className="bg-white dark:bg-secondary p-2 rounded border border-border">
                <span className="text-sm font-medium text-card-foreground">{subdomain}</span>
              </div>
            ))}
          </div>
        </div>
      )

    default:
      return (
        <div className="bg-secondary/30 p-4 rounded-lg border border-border">
          <h4 className="font-medium text-sm mb-3 text-card-foreground">Raw Scan Data</h4>
          <pre className="text-xs bg-secondary p-3 rounded overflow-auto max-h-60 border border-border">
            {JSON.stringify(details, null, 2)}
          </pre>
        </div>
      )
  }
}

export default function ReportsPage() {
  const [individualReports, setIndividualReports] = useState<IndividualReport[]>([])
  const [comprehensiveReports, setComprehensiveReports] = useState<ComprehensiveReport[]>([])
  const [selectedReports, setSelectedReports] = useState<string[]>([])
  const [comprehensiveReportTitle, setComprehensiveReportTitle] = useState("")
  const [loading, setLoading] = useState(false)
  const [generating, setGenerating] = useState(false)
  const [error, setError] = useState("")
  const [success, setSuccess] = useState("")
  const [selectedReportDetail, setSelectedReportDetail] = useState<IndividualReport | ComprehensiveReport | null>(null)

  // Fetch reports on component mount
  useEffect(() => {
    fetchIndividualReports()
    fetchComprehensiveReports()
  }, [])

  const fetchIndividualReports = async () => {
    try {
      setLoading(true)
      console.log('Fetching individual reports...')
      const response = await fetch('/api/reports/individual')
      const data = await response.json()
      
      console.log('Individual reports response:', data)
      
      if (data.success) {
        setIndividualReports(data.reports)
        console.log('Set individual reports:', data.reports)
      } else {
        console.error('Failed to fetch reports:', data.error)
        setError(data.error || 'Failed to fetch individual reports')
      }
    } catch (error) {
      console.error('Error fetching individual reports:', error)
      setError('Failed to fetch individual reports')
    } finally {
      setLoading(false)
    }
  }

  const fetchComprehensiveReports = async () => {
    try {
      const response = await fetch('/api/reports/comprehensive')
      const data = await response.json()
      
      if (data.success) {
        setComprehensiveReports(data.reports)
      }
    } catch (error) {
      console.error('Error fetching comprehensive reports:', error)
    }
  }

  const handleSelectReport = (reportId: string) => {
    setSelectedReports(prev => 
      prev.includes(reportId) 
        ? prev.filter(id => id !== reportId)
        : [...prev, reportId]
    )
  }

  const handleSelectAllReports = () => {
    if (selectedReports.length === individualReports.length) {
      setSelectedReports([])
    } else {
      setSelectedReports(individualReports.map(report => report.id))
    }
  }

  const handleGenerateComprehensiveReport = async () => {
    if (selectedReports.length === 0) {
      setError("Please select at least one report to include")
      return
    }

    if (!comprehensiveReportTitle.trim()) {
      setError("Please enter a report title")
      return
    }

    try {
      setGenerating(true)
      setError("")
      
      const response = await fetch('/api/reports/comprehensive/generate', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          title: comprehensiveReportTitle,
          included_reports: selectedReports
        }),
      })
      
      const data = await response.json()
      
      if (data.success) {
        setSuccess(`Comprehensive report "${comprehensiveReportTitle}" generated successfully!`)
        setComprehensiveReportTitle("")
        setSelectedReports([])
        fetchComprehensiveReports()
      } else {
        setError(data.error || 'Failed to generate comprehensive report')
      }
    } catch (error) {
      console.error('Error generating comprehensive report:', error)
      setError('Failed to generate comprehensive report')
    } finally {
      setGenerating(false)
    }
  }

  const handleDownloadPDF = async (reportId: string, reportType: 'individual' | 'comprehensive') => {
    try {
      const response = await fetch(`/api/reports/download-pdf/${reportType}/${reportId}`, {
        method: 'POST'
      })
      
      if (response.ok) {
        const blob = await response.blob()
        const url = window.URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = `${reportType}-report-${reportId}.pdf`
        document.body.appendChild(a)
        a.click()
        window.URL.revokeObjectURL(url)
        document.body.removeChild(a)
        
        setSuccess(`${reportType} report downloaded successfully!`)
      } else {
        setError('Failed to download report')
      }
    } catch (error) {
      console.error('Error downloading report:', error)
      setError('Failed to download report')
    }
  }

  const handleViewReportDetail = async (reportId: string) => {
    try {
      const response = await fetch(`/api/reports/individual/detail/${reportId}`)
      const data = await response.json()
      
      if (data.success) {
        setSelectedReportDetail(data.report)
      } else {
        setError('Failed to load report details')
      }
    } catch (error) {
      console.error('Error fetching report details:', error)
      setError('Failed to load report details')
    }
  }

  const handleViewComprehensiveReportDetail = async (reportId: string) => {
    try {
      const response = await fetch(`/api/reports/comprehensive/detail/${reportId}`)
      const data = await response.json()
      
      if (data.success) {
        setSelectedReportDetail(data.report)
      } else {
        // If report not found, refresh the comprehensive reports list
        if (data.error && data.error.includes('not found')) {
          setError('Report not found. Refreshing reports list...')
          fetchComprehensiveReports()
        } else {
          setError('Failed to load comprehensive report details')
        }
      }
    } catch (error) {
      console.error('Error fetching comprehensive report details:', error)
      setError('Failed to load comprehensive report details')
    }
  }

  const handleDeleteReport = async (reportId: string, reportType: 'individual' | 'comprehensive') => {
    if (!confirm(`Are you sure you want to delete this ${reportType} report?`)) {
      return
    }

    try {
      const response = await fetch(`/api/reports/delete/${reportType}/${reportId}`, {
        method: 'DELETE'
      })
      
      const data = await response.json()
      
      if (data.success) {
        setSuccess(`${reportType} report deleted successfully!`)
        if (reportType === 'individual') {
          fetchIndividualReports()
        } else {
          fetchComprehensiveReports()
        }
      } else {
        setError(data.error || 'Failed to delete report')
      }
    } catch (error) {
      console.error('Error deleting report:', error)
      setError('Failed to delete report')
    }
  }

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case "critical":
        return "bg-red-600"
      case "high":
        return "bg-orange-600"
      case "medium":
        return "bg-yellow-600"
      case "low":
        return "bg-blue-600"
      default:
        return "bg-gray-600"
    }
  }

  const getScanTypeIcon = (type: string) => {
    switch (type) {
      case 'whois':
        return <Info className="h-4 w-4" />
      case 'dns':
        return <Globe className="h-4 w-4" />
      case 'subdomain':
        return <Search className="h-4 w-4" />
      case 'port_scan':
        return <Network className="h-4 w-4" />
      case 'vulnerability_scan':
        return <Zap className="h-4 w-4" />
      case 'exploit':
        return <AlertTriangle className="h-4 w-4" />
      default:
        return <FileText className="h-4 w-4" />
    }
  }

  const getScanTypeName = (type: string) => {
    if (!type) return 'Unknown Scan Type'

    switch (type) {
      case 'whois':
        return 'WHOIS Lookup'
      case 'dns':
        return 'DNS Enumeration'
      case 'subdomain':
        return 'Subdomain Enumeration'
      case 'port_scan':
        return 'Port Scanning'
      case 'vulnerability_scan':
        return 'Vulnerability Assessment'
      case 'exploit':
        return 'Exploitation'
      default:
        return type.replace('_', ' ').toUpperCase()
    }
  }

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString()
  }

  const formatTime = (dateString: string) => {
    return new Date(dateString).toLocaleTimeString()
  }

  // Type guard to check if report is individual
  const isIndividualReport = (report: IndividualReport | ComprehensiveReport): report is IndividualReport => {
    return 'scan_type' in report && 'target' in report
  }

  return (
    <div className="space-y-4 sm:space-y-6">
      <div>
        <h1 className="text-2xl sm:text-3xl font-bold text-white mb-2">Security Reports</h1>
        <p className="text-slate-400 text-sm sm:text-base">Manage individual scan reports and generate comprehensive security assessments</p>
      </div>

      {error && (
        <Alert className="border-red-500 bg-red-50 dark:bg-red-900/20">
          <AlertTriangle className="h-4 w-4 text-red-500" />
          <AlertDescription className="text-red-700 dark:text-red-300">{error}</AlertDescription>
        </Alert>
      )}

      {success && (
        <Alert className="border-green-500 bg-green-50 dark:bg-green-900/20">
          <CheckCircle className="h-4 w-4 text-green-500" />
          <AlertDescription className="text-green-700 dark:text-green-300">{success}</AlertDescription>
        </Alert>
      )}

      <Tabs defaultValue="individual" className="w-full">
        <TabsList className="grid w-full grid-cols-3">
          <TabsTrigger value="individual">Individual Reports</TabsTrigger>
          <TabsTrigger value="comprehensive">Comprehensive Reports</TabsTrigger>
          <TabsTrigger value="generate">Generate Report</TabsTrigger>
        </TabsList>

        <TabsContent value="individual" className="space-y-4">
              <Card>
                <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle className="text-lg sm:text-xl">Individual Scan Reports</CardTitle>
                  <CardDescription className="text-sm">
                    Individual reports from reconnaissance, scanning, and exploitation activities
                  </CardDescription>
                    </div>
                <Badge className="bg-blue-600">{individualReports.length} reports</Badge>
                    </div>
            </CardHeader>
            <CardContent>
              {loading ? (
                <div className="text-center py-8">
                  <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 mx-auto"></div>
                  <p className="text-muted-foreground mt-2">Loading reports...</p>
                </div>
              ) : individualReports.length === 0 ? (
                <div className="text-center py-8">
                  <FileText className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
                  <p className="text-muted-foreground">No individual reports available</p>
                  <p className="text-sm text-muted-foreground">Complete scans and exploits to generate reports</p>
                </div>
              ) : (
                <div className="space-y-4">
                  {individualReports.map((report) => (
                    <div key={report.id} className="p-4 bg-secondary rounded-lg border border-border">
                      <div className="flex items-start justify-between mb-3">
                        <div className="flex items-center gap-3">
                          {getScanTypeIcon(report.scan_type)}
                          <div>
                            <h3 className="text-foreground font-medium">{report.title}</h3>
                            <p className="text-muted-foreground text-sm">{getScanTypeName(report.scan_type)}</p>
                      </div>
                            </div>
                        <div className="flex items-center gap-2">
                          <Badge className={getSeverityColor(report.severity)}>{report.severity}</Badge>
                          <Badge variant="outline">{report.findings_count} findings</Badge>
                                </div>
                                </div>
                      
                      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-3">
                        <div className="flex items-center space-x-2">
                          <Target className="h-3 w-3 sm:h-4 sm:w-4 text-muted-foreground" />
                          <span className="text-foreground text-xs sm:text-sm truncate">{report.target}</span>
                                </div>
                        <div className="flex items-center space-x-2">
                          <Calendar className="h-3 w-3 sm:h-4 sm:w-4 text-muted-foreground" />
                          <span className="text-foreground text-xs sm:text-sm">{formatDate(report.timestamp)}</span>
                                </div>
                        <div className="flex items-center space-x-2">
                          <Activity className="h-3 w-3 sm:h-4 sm:w-4 text-muted-foreground" />
                          <span className="text-foreground text-xs sm:text-sm">{formatTime(report.timestamp)}</span>
                                </div>
                        <div className="flex items-center space-x-2">
                          <FileText className="h-3 w-3 sm:h-4 sm:w-4 text-muted-foreground" />
                          <span className="text-foreground text-xs sm:text-sm">{report.status}</span>
                              </div>
                              </div>

                      <p className="text-sm text-muted-foreground mb-3">{report.summary}</p>

                      <div className="flex flex-col sm:flex-row gap-2">
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => handleViewReportDetail(report.id)}
                        >
                          <Eye className="h-3 w-3 sm:h-4 sm:w-4 mr-1" />
                          View Details
                        </Button>
                        <Button 
                          size="sm" 
                          className="bg-blue-600 hover:bg-blue-700"
                          onClick={() => handleDownloadPDF(report.id, 'individual')}
                        >
                          <FileDown className="h-3 w-3 sm:h-4 sm:w-4 mr-1" />
                          Download PDF
                        </Button>
                        <Button
                          size="sm"
                          variant="outline"
                          className="text-red-600 hover:text-red-700"
                          onClick={() => handleDeleteReport(report.id, 'individual')}
                        >
                          <Trash2 className="h-3 w-3 sm:h-4 sm:w-4 mr-1" />
                          Delete
                        </Button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="comprehensive" className="space-y-4">
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle className="text-lg sm:text-xl">Comprehensive Reports</CardTitle>
              <CardDescription className="text-sm">
                    Comprehensive security assessment reports combining multiple individual reports
              </CardDescription>
                </div>
                <div className="flex items-center gap-2">
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={fetchComprehensiveReports}
                    className="text-xs"
                  >
                    <RefreshCw className="h-3 w-3 mr-1" />
                    Refresh
                  </Button>
                  <Badge className="bg-green-600">{comprehensiveReports.length} reports</Badge>
                </div>
              </div>
            </CardHeader>
            <CardContent>
              {comprehensiveReports.length === 0 ? (
                <div className="text-center py-8">
                  <FileText className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
                  <p className="text-muted-foreground">No comprehensive reports generated yet</p>
                  <p className="text-sm text-muted-foreground">Select individual reports to generate comprehensive assessments</p>
                </div>
              ) : (
                <div className="space-y-4">
                  {comprehensiveReports.map((report) => (
                    <div key={report.id} className="p-4 bg-secondary rounded-lg border border-border">
                      <div className="flex items-start justify-between mb-3">
                        <div>
                          <h3 className="text-foreground font-medium">{report.title}</h3>
                          <p className="text-muted-foreground text-sm">
                            Generated on {formatDate(report.generated_at)} at {formatTime(report.generated_at)}
                          </p>
                        </div>
                        <div className="flex items-center gap-2">
                          <Badge className={getSeverityColor(report.overall_severity)}>{report.overall_severity}</Badge>
                          <Badge variant="outline">{report.total_findings} findings</Badge>
                          <Badge variant="outline">{report.included_reports.length} reports</Badge>
                        </div>
                      </div>

                      <div className="flex flex-col sm:flex-row gap-2">
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => handleViewComprehensiveReportDetail(report.id)}
                        >
                          <Eye className="h-3 w-3 sm:h-4 sm:w-4 mr-1" />
                          View Details
                        </Button>
                        <Button 
                          size="sm" 
                          className="bg-green-600 hover:bg-green-700"
                          onClick={() => handleDownloadPDF(report.id, 'comprehensive')}
                        >
                          <FileDown className="h-3 w-3 sm:h-4 sm:w-4 mr-1" />
                          Download PDF
                        </Button>
                        <Button
                          size="sm"
                          variant="outline"
                          className="text-red-600 hover:text-red-700"
                          onClick={() => handleDeleteReport(report.id, 'comprehensive')}
                        >
                          <Trash2 className="h-3 w-3 sm:h-4 sm:w-4 mr-1" />
                          Delete
                        </Button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="generate" className="space-y-4">
            <Card>
              <CardHeader>
              <CardTitle className="text-lg sm:text-xl">Generate Comprehensive Report</CardTitle>
                <CardDescription className="text-sm">
                Select individual reports to combine into a comprehensive security assessment
                </CardDescription>
              </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="report-title" className="text-foreground text-sm">
                  Comprehensive Report Title
                </Label>
                <Input
                  id="report-title"
                  value={comprehensiveReportTitle}
                  onChange={(e) => setComprehensiveReportTitle(e.target.value)}
                  placeholder="Comprehensive Security Assessment Report"
                  className="bg-secondary border-border text-foreground"
                />
                    </div>

              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <Label className="text-foreground text-sm">Select Reports to Include</Label>
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={handleSelectAllReports}
                  >
                    {selectedReports.length === individualReports.length ? (
                      <>
                        <Square className="h-3 w-3 sm:h-4 sm:w-4 mr-1" />
                        Deselect All
                      </>
                    ) : (
                      <>
                        <CheckSquare className="h-3 w-3 sm:h-4 sm:w-4 mr-1" />
                        Select All
                      </>
                    )}
                  </Button>
                  </div>

                {individualReports.length === 0 ? (
                  <div className="text-center py-8">
                    <FileText className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
                    <p className="text-muted-foreground">No individual reports available</p>
                    <p className="text-sm text-muted-foreground">Complete scans and exploits to generate individual reports first</p>
                        </div>
                ) : (
                  <div className="space-y-2 max-h-96 overflow-y-auto">
                    {individualReports.map((report) => (
                      <div key={report.id} className="flex items-center space-x-3 p-3 bg-background rounded-lg border">
                        <Checkbox
                          id={report.id}
                          checked={selectedReports.includes(report.id)}
                          onCheckedChange={() => handleSelectReport(report.id)}
                        />
                        <div className="flex-1">
                          <div className="flex items-center gap-2">
                            {getScanTypeIcon(report.scan_type)}
                            <span className="font-medium text-sm">{report.title}</span>
                            <Badge className={getSeverityColor(report.severity)}>{report.severity}</Badge>
                        </div>
                          <p className="text-xs text-muted-foreground">{report.target} • {getScanTypeName(report.scan_type)}</p>
                        </div>
                        <Badge variant="outline">{report.findings_count} findings</Badge>
                      </div>
                        ))}
                          </div>
                        )}
              </div>

                      <div className="space-y-2">
                <Button
                  onClick={handleGenerateComprehensiveReport}
                  disabled={selectedReports.length === 0 || !comprehensiveReportTitle.trim() || generating}
                  className="w-full bg-green-600 hover:bg-green-700"
                >
                  <Plus className="h-4 w-4 mr-2" />
                  {generating ? 'Generating...' : 'Generate Comprehensive Report'}
                </Button>
                
                {/* Debug info to help identify why button is disabled */}
                <div className="text-xs text-muted-foreground space-y-1">
                  <div>Available reports: {individualReports.length}</div>
                  <div>Selected reports: {selectedReports.length}</div>
                  <div>Title entered: {comprehensiveReportTitle ? 'Yes' : 'No'}</div>
                  <div>Currently generating: {generating ? 'Yes' : 'No'}</div>
                  <div>Button disabled: {selectedReports.length === 0 || !comprehensiveReportTitle.trim() || generating ? 'Yes' : 'No'}</div>
                          </div>
                          </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {/* Report Detail Modal */}
      {selectedReportDetail && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <Card className="w-full max-w-4xl max-h-[90vh] overflow-hidden bg-card border-border">
            <CardHeader className="border-b border-border bg-card">
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle className="text-lg sm:text-xl flex items-center gap-2 text-card-foreground">
                    {isIndividualReport(selectedReportDetail) ? getScanTypeIcon(selectedReportDetail.scan_type) : <FileText className="h-4 w-4" />}
                    {selectedReportDetail.title}
                  </CardTitle>
                  <CardDescription className="text-sm text-muted-foreground">
                    {isIndividualReport(selectedReportDetail) ? 
                      `${getScanTypeName(selectedReportDetail.scan_type)} on ${selectedReportDetail.target}` :
                      `Comprehensive Report - Generated on ${formatDate(selectedReportDetail.generated_at)}`
                    }
                  </CardDescription>
                </div>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => setSelectedReportDetail(null)}
                  className="text-muted-foreground hover:text-foreground"
                >
                  <X className="h-4 w-4" />
                </Button>
              </div>
            </CardHeader>
            
            <CardContent className="p-0 bg-card">
              <div className="overflow-y-auto max-h-[calc(90vh-120px)]">
                <div className="p-6 space-y-6">
                  {/* Report Overview */}
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    {isIndividualReport(selectedReportDetail) ? (
                      <>
                        <div className="bg-secondary/50 p-4 rounded-lg border border-border">
                          <div className="flex items-center gap-2 mb-2">
                            <Target className="h-4 w-4 text-blue-500" />
                            <span className="font-medium text-sm text-card-foreground">Target</span>
                          </div>
                          <p className="text-sm text-muted-foreground">{selectedReportDetail.target}</p>
                        </div>
                        
                        <div className="bg-secondary/50 p-4 rounded-lg border border-border">
                          <div className="flex items-center gap-2 mb-2">
                            <Calendar className="h-4 w-4 text-green-500" />
                            <span className="font-medium text-sm text-card-foreground">Scan Date</span>
                          </div>
                          <p className="text-sm text-muted-foreground">{formatDate(selectedReportDetail.timestamp)}</p>
                        </div>
                        
                        <div className="bg-secondary/50 p-4 rounded-lg border border-border">
                          <div className="flex items-center gap-2 mb-2">
                            <Badge className={getSeverityColor(selectedReportDetail.severity)}>
                              {selectedReportDetail.severity}
                            </Badge>
                            <span className="font-medium text-sm text-card-foreground">Severity</span>
                          </div>
                          <p className="text-sm text-muted-foreground">{selectedReportDetail.findings_count} findings</p>
                        </div>
                      </>
                    ) : (
                      <>
                        <div className="bg-secondary/50 p-4 rounded-lg border border-border">
                          <div className="flex items-center gap-2 mb-2">
                            <Calendar className="h-4 w-4 text-green-500" />
                            <span className="font-medium text-sm text-card-foreground">Generated Date</span>
                          </div>
                          <p className="text-sm text-muted-foreground">{formatDate(selectedReportDetail.generated_at)}</p>
                        </div>
                        
                        <div className="bg-secondary/50 p-4 rounded-lg border border-border">
                          <div className="flex items-center gap-2 mb-2">
                            <Badge className={getSeverityColor(selectedReportDetail.overall_severity)}>
                              {selectedReportDetail.overall_severity}
                            </Badge>
                            <span className="font-medium text-sm text-card-foreground">Overall Severity</span>
                          </div>
                          <p className="text-sm text-muted-foreground">{selectedReportDetail.total_findings} findings</p>
                        </div>
                        
                        <div className="bg-secondary/50 p-4 rounded-lg border border-border">
                          <div className="flex items-center gap-2 mb-2">
                            <FileText className="h-4 w-4 text-blue-500" />
                            <span className="font-medium text-sm text-card-foreground">Included Reports</span>
                          </div>
                          <p className="text-sm text-muted-foreground">{selectedReportDetail.included_reports.length} reports</p>
                        </div>
                      </>
                        )}
                      </div>

                  {/* Summary Section */}
                  {isIndividualReport(selectedReportDetail) ? (
                    <>
                      {/* Scan Summary */}
                      <div className="bg-secondary/30 p-4 rounded-lg border border-border">
                        <h3 className="text-base font-semibold text-card-foreground mb-3 flex items-center gap-2">
                          <Info className="h-4 w-4 text-blue-500" />
                          Scan Summary
                        </h3>
                        <p className="text-sm text-muted-foreground leading-relaxed">
                          {selectedReportDetail.summary}
                        </p>
                      </div>

                      {/* Scan Results */}
                      <div className="space-y-4">
                        <h3 className="text-base font-semibold text-card-foreground flex items-center gap-2">
                          <Activity className="h-4 w-4 text-green-500" />
                          Scan Results
                        </h3>
                        
                        {renderScanResults(selectedReportDetail.details, selectedReportDetail.scan_type)}
                      </div>
                    </>
                  ) : (
                    <>
                      {/* Comprehensive Report Summary */}
                      <div className="bg-secondary/30 p-4 rounded-lg border border-border">
                        <h3 className="text-base font-semibold text-card-foreground mb-3 flex items-center gap-2">
                          <Info className="h-4 w-4 text-blue-500" />
                          Comprehensive Report Summary
                        </h3>
                        <p className="text-sm text-muted-foreground leading-relaxed">
                          This comprehensive report combines {selectedReportDetail.included_reports.length} individual reports with a total of {selectedReportDetail.total_findings} findings.
                        </p>
                      </div>

                      {/* Included Reports */}
                      <div className="space-y-4">
                        <h3 className="text-base font-semibold text-card-foreground flex items-center gap-2">
                          <FileText className="h-4 w-4 text-green-500" />
                          Included Reports
                        </h3>
                        
                        <div className="space-y-2">
                          {selectedReportDetail.included_reports.map((reportId, index) => (
                            <div key={index} className="p-3 bg-secondary/50 rounded-lg border border-border">
                              <p className="text-sm text-muted-foreground">Report ID: {reportId}</p>
                            </div>
                          ))}
                        </div>
                      </div>
                    </>
                  )}
                  </div>
                </div>
              </CardContent>
            
            <div className="border-t border-border p-4 bg-secondary/20">
              <div className="flex gap-2 justify-end">
                <Button
                  size="sm"
                  className="bg-blue-600 hover:bg-blue-700"
                  onClick={() => handleDownloadPDF(selectedReportDetail.id, isIndividualReport(selectedReportDetail) ? 'individual' : 'comprehensive')}
                >
                  <FileDown className="h-4 w-4 mr-2" />
                  Download PDF
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => setSelectedReportDetail(null)}
                >
                  Close
                </Button>
              </div>
            </div>
            </Card>
        </div>
          )}
    </div>
  )
}
