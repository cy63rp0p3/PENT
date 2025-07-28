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
import { FileText, Download, Eye, Calendar, User, Target, AlertTriangle, CheckCircle, Info, BarChart3, Shield, Zap } from "lucide-react"

interface ScanResult {
  type: string
  target: string
  results: any
  timestamp: string
  status: string
}

interface Report {
  id: string
  title: string
  type: string
  target: string
  generated_at: string
  findings_count: number
  severity: string
}

interface ReportDetail {
  title: string
  type: string
  target: string
  generated_at: string
  sections: string[]
  executive_summary: any
  findings: any[]
  recommendations: any[]
  technical_details: any
}

export default function ReportsPage() {
  const [reportTitle, setReportTitle] = useState("")
  const [reportType, setReportType] = useState("")
  const [selectedTarget, setSelectedTarget] = useState("")
  const [includeSections, setIncludeSections] = useState([
    "Executive Summary",
    "Methodology", 
    "Findings & Vulnerabilities",
    "Risk Assessment",
    "Recommendations",
    "Technical Details",
    "Appendices",
  ])
  const [scanResults, setScanResults] = useState<ScanResult[]>([])
  const [reports, setReports] = useState<Report[]>([])
  const [selectedReport, setSelectedReport] = useState<ReportDetail | null>(null)
  const [loading, setLoading] = useState(false)
  const [generating, setGenerating] = useState(false)
  const [error, setError] = useState("")
  const [success, setSuccess] = useState("")

  // Fetch scan results and reports on component mount
  useEffect(() => {
    fetchScanResults()
    fetchReports()
  }, [])

  const fetchScanResults = async () => {
    try {
      setLoading(true)
      const response = await fetch('/api/reports?action=scan-results')
      const data = await response.json()
      
      if (data.success) {
        const results = Object.values(data.results) as ScanResult[]
        setScanResults(results)
        
        // Get unique targets for dropdown
        const targets = [...new Set(results.map(result => result.target))]
        if (targets.length > 0 && !selectedTarget) {
          setSelectedTarget(targets[0])
        }
      }
    } catch (error) {
      console.error('Error fetching scan results:', error)
      setError('Failed to fetch scan results')
    } finally {
      setLoading(false)
    }
  }

  const fetchReports = async () => {
    try {
      const response = await fetch('/api/reports?action=list')
      const data = await response.json()
      
      if (data.success) {
        setReports(data.reports)
      }
    } catch (error) {
      console.error('Error fetching reports:', error)
    }
  }

  const handleGenerateReport = async () => {
    if (!reportTitle || !reportType || !selectedTarget) {
      setError("Please fill in all required fields")
      return
    }

    try {
      setGenerating(true)
      setError("")
      
      const response = await fetch('/api/reports', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          action: 'generate',
          title: reportTitle,
          type: reportType,
          target: selectedTarget,
          sections: includeSections
        }),
      })
      
      const data = await response.json()
      
      if (data.success) {
        setSuccess(`Report "${reportTitle}" generated successfully!`)
        setReportTitle("")
        setReportType("")
        fetchReports() // Refresh reports list
      } else {
        setError(data.error || 'Failed to generate report')
      }
    } catch (error) {
      console.error('Error generating report:', error)
      setError('Failed to generate report')
    } finally {
      setGenerating(false)
    }
  }

  const handleViewReport = async (reportId: string) => {
    try {
      const response = await fetch(`/api/reports/${reportId}`)
      const data = await response.json()
      
      if (data.success) {
        setSelectedReport(data.report)
      } else {
        setError('Failed to load report details')
      }
    } catch (error) {
      console.error('Error fetching report details:', error)
      setError('Failed to load report details')
    }
  }

  const getSeverityColor = (severity: string) => {
    switch (severity) {
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

  const getStatusColor = (status: string) => {
    switch (status) {
      case "completed":
        return "bg-green-600"
      case "draft":
        return "bg-yellow-600"
      case "in-progress":
        return "bg-blue-600"
      default:
        return "bg-gray-600"
    }
  }

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString()
  }

  const getScanTypeIcon = (type: string) => {
    switch (type) {
      case 'whois':
        return <Info className="h-4 w-4" />
      case 'dns':
        return <Target className="h-4 w-4" />
      case 'subdomain':
        return <BarChart3 className="h-4 w-4" />
      case 'port_scan':
        return <Shield className="h-4 w-4" />
      case 'vulnerability_scan':
        return <Zap className="h-4 w-4" />
      default:
        return <FileText className="h-4 w-4" />
    }
  }

  return (
    <div className="space-y-4 sm:space-y-6">
      <div>
        <h1 className="text-2xl sm:text-3xl font-bold text-white mb-2">Reports</h1>
        <p className="text-slate-400 text-sm sm:text-base">Generate and manage security assessment reports</p>
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

      <Tabs defaultValue="generate" className="w-full">
        <TabsList className="grid w-full grid-cols-3">
          <TabsTrigger value="generate">Generate Report</TabsTrigger>
          <TabsTrigger value="results">Scan Results</TabsTrigger>
          <TabsTrigger value="reports">Existing Reports</TabsTrigger>
        </TabsList>

        <TabsContent value="generate" className="space-y-4">
          <div className="grid grid-cols-1 xl:grid-cols-3 gap-4 sm:gap-6">
            <div className="xl:col-span-1">
              <Card className="bg-card border-border">
                <CardHeader>
                  <CardTitle className="text-foreground text-lg sm:text-xl">Generate New Report</CardTitle>
                  <CardDescription className="text-muted-foreground text-sm">
                    Create a comprehensive security assessment report from scan results
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="space-y-2">
                    <Label htmlFor="title" className="text-foreground text-sm">
                      Report Title
                    </Label>
                    <Input
                      id="title"
                      value={reportTitle}
                      onChange={(e) => setReportTitle(e.target.value)}
                      placeholder="Security Assessment Report"
                      className="bg-secondary border-border text-foreground text-sm sm:text-base"
                    />
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="type" className="text-foreground text-sm">
                      Report Type
                    </Label>
                    <Select value={reportType} onValueChange={setReportType}>
                      <SelectTrigger className="bg-secondary border-border text-foreground text-sm sm:text-base">
                        <SelectValue placeholder="Select report type" />
                      </SelectTrigger>
                      <SelectContent className="bg-secondary border-border">
                        <SelectItem value="web">Web Application Pentest</SelectItem>
                        <SelectItem value="network">Network Pentest</SelectItem>
                        <SelectItem value="mobile">Mobile Application Pentest</SelectItem>
                        <SelectItem value="cloud">Cloud Security Assessment</SelectItem>
                        <SelectItem value="comprehensive">Comprehensive Assessment</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="target" className="text-foreground text-sm">
                      Target Domain
                    </Label>
                    <Select value={selectedTarget} onValueChange={setSelectedTarget}>
                      <SelectTrigger className="bg-secondary border-border text-foreground text-sm sm:text-base">
                        <SelectValue placeholder="Select target domain" />
                      </SelectTrigger>
                      <SelectContent className="bg-secondary border-border">
                        {[...new Set(scanResults.map(result => result.target))].map((target) => (
                          <SelectItem key={target} value={target}>
                            {target}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>

                  <div className="space-y-2">
                    <Label className="text-foreground text-sm">Include Sections</Label>
                    <div className="space-y-2 max-h-48 overflow-y-auto">
                      {[
                        "Executive Summary",
                        "Methodology",
                        "Findings & Vulnerabilities",
                        "Risk Assessment",
                        "Recommendations",
                        "Technical Details",
                        "Appendices",
                      ].map((section) => (
                        <div key={section} className="flex items-center space-x-2">
                          <input
                            type="checkbox"
                            id={section}
                            checked={includeSections.includes(section)}
                            onChange={(e) => {
                              if (e.target.checked) {
                                setIncludeSections([...includeSections, section])
                              } else {
                                setIncludeSections(includeSections.filter(s => s !== section))
                              }
                            }}
                            className="rounded bg-secondary border-border"
                          />
                          <label htmlFor={section} className="text-foreground text-sm">
                            {section}
                          </label>
                        </div>
                      ))}
                    </div>
                  </div>

                  <Button
                    onClick={handleGenerateReport}
                    disabled={!reportTitle || !reportType || !selectedTarget || generating}
                    className="w-full bg-green-600 hover:bg-green-700 text-sm sm:text-base"
                  >
                    <FileText className="h-4 w-4 mr-2" />
                    {generating ? 'Generating...' : 'Generate Report'}
                  </Button>
                </CardContent>
              </Card>
            </div>

            <div className="xl:col-span-2">
              <Card>
                <CardHeader>
                  <CardTitle className="text-lg sm:text-xl">Available Scan Results</CardTitle>
                  <CardDescription className="text-sm">
                    Select a target domain to generate a report from available scan data
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  {loading ? (
                    <div className="text-center py-8">
                      <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 mx-auto"></div>
                      <p className="text-muted-foreground mt-2">Loading scan results...</p>
                    </div>
                  ) : scanResults.length === 0 ? (
                    <div className="text-center py-8">
                      <FileText className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
                      <p className="text-muted-foreground">No scan results available</p>
                      <p className="text-sm text-muted-foreground">Run some scans first to generate reports</p>
                    </div>
                  ) : (
                    <div className="space-y-4">
                      {Object.entries(
                        scanResults.reduce((acc, result) => {
                          if (!acc[result.target]) {
                            acc[result.target] = []
                          }
                          acc[result.target].push(result)
                          return acc
                        }, {} as Record<string, ScanResult[]>)
                      ).map(([target, results]) => (
                        <div key={target} className="p-4 bg-secondary rounded-lg border border-border">
                          <div className="flex items-center justify-between mb-3">
                            <h3 className="text-foreground font-medium">{target}</h3>
                            <Badge className="bg-blue-600">{results.length} scans</Badge>
                          </div>
                          <div className="grid grid-cols-2 sm:grid-cols-5 gap-2">
                            {results.map((result) => (
                              <div key={`${target}-${result.type}`} className="flex items-center gap-2 text-sm">
                                {getScanTypeIcon(result.type)}
                                <span className="capitalize">{result.type.replace('_', ' ')}</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </CardContent>
              </Card>
            </div>
          </div>
        </TabsContent>

        <TabsContent value="results" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-lg sm:text-xl">Scan Results Visualization</CardTitle>
              <CardDescription className="text-sm">
                View detailed results from all completed scans
              </CardDescription>
            </CardHeader>
            <CardContent>
              {loading ? (
                <div className="text-center py-8">
                  <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 mx-auto"></div>
                  <p className="text-muted-foreground mt-2">Loading scan results...</p>
                </div>
              ) : scanResults.length === 0 ? (
                <div className="text-center py-8">
                  <FileText className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
                  <p className="text-muted-foreground">No scan results available</p>
                </div>
              ) : (
                <div className="space-y-4">
                  {Object.entries(
                    scanResults.reduce((acc, result) => {
                      if (!acc[result.target]) {
                        acc[result.target] = []
                      }
                      acc[result.target].push(result)
                      return acc
                    }, {} as Record<string, ScanResult[]>)
                  ).map(([target, results]) => (
                    <div key={target} className="p-4 bg-secondary rounded-lg border border-border">
                      <div className="flex items-center justify-between mb-4">
                        <h3 className="text-foreground font-semibold text-lg">{target}</h3>
                        <Badge className="bg-green-600">{results.length} completed scans</Badge>
                      </div>
                      
                      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                        {results.map((result) => (
                          <div key={`${target}-${result.type}`} className="p-3 bg-background rounded-lg border">
                            <div className="flex items-center gap-2 mb-2">
                              {getScanTypeIcon(result.type)}
                              <span className="font-medium capitalize">{result.type.replace('_', ' ')}</span>
                            </div>
                            
                            {result.type === 'vulnerability_scan' && result.results && (
                              <div className="space-y-2 text-sm">
                                <div className="flex justify-between">
                                  <span className="text-red-500">Critical:</span>
                                  <span>{result.results.critical_vulnerabilities?.length || 0}</span>
                                </div>
                                <div className="flex justify-between">
                                  <span className="text-orange-500">High:</span>
                                  <span>{result.results.high_vulnerabilities?.length || 0}</span>
                                </div>
                                <div className="flex justify-between">
                                  <span className="text-yellow-500">Medium:</span>
                                  <span>{result.results.medium_vulnerabilities?.length || 0}</span>
                                </div>
                                <div className="flex justify-between">
                                  <span className="text-blue-500">Low:</span>
                                  <span>{result.results.low_vulnerabilities?.length || 0}</span>
                                </div>
                              </div>
                            )}
                            
                            {result.type === 'port_scan' && result.results && (
                              <div className="space-y-2 text-sm">
                                <div className="flex justify-between">
                                  <span>Open Ports:</span>
                                  <span>{result.results.open_ports?.length || 0}</span>
                                </div>
                                <div className="flex justify-between">
                                  <span>Closed Ports:</span>
                                  <span>{result.results.closed_ports?.length || 0}</span>
                                </div>
                                <div className="flex justify-between">
                                  <span>Filtered Ports:</span>
                                  <span>{result.results.filtered_ports?.length || 0}</span>
                                </div>
                              </div>
                            )}
                            
                            {result.type === 'whois' && result.results && (
                              <div className="text-sm text-muted-foreground">
                                Domain info available
                              </div>
                            )}
                            
                            {result.type === 'dns' && result.results && (
                              <div className="text-sm text-muted-foreground">
                                DNS records available
                              </div>
                            )}
                            
                            {result.type === 'subdomain' && result.results && (
                              <div className="text-sm text-muted-foreground">
                                {result.results.subdomains?.length || 0} subdomains found
                              </div>
                            )}
                          </div>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="reports" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-lg sm:text-xl">Generated Reports</CardTitle>
              <CardDescription className="text-sm">
                Browse and download previously generated reports
              </CardDescription>
            </CardHeader>
            <CardContent>
              {reports.length === 0 ? (
                <div className="text-center py-8">
                  <FileText className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
                  <p className="text-muted-foreground">No reports generated yet</p>
                  <p className="text-sm text-muted-foreground">Generate your first report from scan results</p>
                </div>
              ) : (
                <div className="space-y-4">
                  {reports.map((report) => (
                    <div key={report.id} className="p-4 bg-secondary rounded-lg border border-border">
                      <div className="flex flex-col sm:flex-row sm:items-start justify-between mb-3 space-y-2 sm:space-y-0">
                        <div className="min-w-0">
                          <h3 className="text-foreground font-medium mb-1 text-sm sm:text-base break-words">
                            {report.title}
                          </h3>
                          <p className="text-muted-foreground text-xs sm:text-sm">{report.type}</p>
                        </div>
                        <div className="flex flex-wrap gap-2">
                          <Badge className={getSeverityColor(report.severity)}>{report.severity}</Badge>
                        </div>
                      </div>

                      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 sm:gap-4 mb-3">
                        <div className="flex items-center space-x-2">
                          <Calendar className="h-3 w-3 sm:h-4 sm:w-4 text-muted-foreground flex-shrink-0" />
                          <span className="text-foreground text-xs sm:text-sm truncate">
                            {formatDate(report.generated_at)}
                          </span>
                        </div>
                        <div className="flex items-center space-x-2">
                          <Target className="h-3 w-3 sm:h-4 sm:w-4 text-muted-foreground flex-shrink-0" />
                          <span className="text-foreground text-xs sm:text-sm truncate">{report.target}</span>
                        </div>
                        <div className="flex items-center space-x-2 col-span-2 sm:col-span-2">
                          <FileText className="h-3 w-3 sm:h-4 sm:w-4 text-muted-foreground flex-shrink-0" />
                          <span className="text-foreground text-xs sm:text-sm">{report.findings_count} findings</span>
                        </div>
                      </div>

                      <div className="flex flex-col sm:flex-row gap-2">
                        <Button
                          size="sm"
                          variant="outline"
                          className="text-xs sm:text-sm"
                          onClick={() => handleViewReport(report.id)}
                        >
                          <Eye className="h-3 w-3 sm:h-4 sm:w-4 mr-1" />
                          Preview
                        </Button>
                        <Button size="sm" className="bg-blue-600 hover:bg-blue-700 text-xs sm:text-sm">
                          <Download className="h-3 w-3 sm:h-4 sm:w-4 mr-1" />
                          <span className="hidden sm:inline">Download PDF</span>
                          <span className="sm:hidden">PDF</span>
                        </Button>
                        <Button
                          size="sm"
                          variant="outline"
                          className="text-xs sm:text-sm"
                        >
                          <Download className="h-3 w-3 sm:h-4 sm:w-4 mr-1" />
                          <span className="hidden sm:inline">Download HTML</span>
                          <span className="sm:hidden">HTML</span>
                        </Button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>

          {/* Report Detail Modal */}
          {selectedReport && (
            <Card>
              <CardHeader>
                <CardTitle className="text-lg sm:text-xl">Report Preview: {selectedReport.title}</CardTitle>
                <CardDescription className="text-sm">
                  Generated on {formatDate(selectedReport.generated_at)} for {selectedReport.target}
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="bg-background p-4 sm:p-6 rounded-lg text-foreground overflow-auto max-h-96">
                  <div className="border-b pb-4 mb-4">
                    <h1 className="text-xl sm:text-2xl font-bold text-foreground">{selectedReport.title}</h1>
                    <p className="text-muted-foreground text-sm sm:text-base">Comprehensive Security Assessment Results</p>
                    <div className="mt-2 text-xs sm:text-sm text-muted-foreground">
                      Generated on: {formatDate(selectedReport.generated_at)} | Target: {selectedReport.target}
                    </div>
                  </div>

                  <div className="space-y-4">
                    <section>
                      <h2 className="text-base sm:text-lg font-semibold text-foreground mb-2">Executive Summary</h2>
                      <div className="space-y-2">
                        <div className="flex items-center space-x-2">
                          <div className="w-2 h-2 sm:w-3 sm:h-3 bg-red-500 rounded-full flex-shrink-0"></div>
                          <span className="text-xs sm:text-sm text-muted-foreground">
                            {selectedReport.executive_summary.critical_count} Critical vulnerabilities identified
                          </span>
                        </div>
                        <div className="flex items-center space-x-2">
                          <div className="w-2 h-2 sm:w-3 sm:h-3 bg-orange-500 rounded-full flex-shrink-0"></div>
                          <span className="text-xs sm:text-sm text-muted-foreground">
                            {selectedReport.executive_summary.high_count} High severity issues found
                          </span>
                        </div>
                        <div className="flex items-center space-x-2">
                          <div className="w-2 h-2 sm:w-3 sm:h-3 bg-yellow-500 rounded-full flex-shrink-0"></div>
                          <span className="text-xs sm:text-sm text-muted-foreground">
                            {selectedReport.executive_summary.medium_count} Medium risk vulnerabilities
                          </span>
                        </div>
                      </div>
                    </section>

                    <section>
                      <h2 className="text-base sm:text-lg font-semibold text-foreground mb-2">Key Findings</h2>
                      <div className="space-y-2">
                        {selectedReport.findings.slice(0, 5).map((finding, index) => (
                          <div key={index} className="p-2 bg-secondary rounded border-l-4 border-red-500">
                            <div className="font-medium text-sm">{finding.title}</div>
                            <div className="text-xs text-muted-foreground">{finding.description}</div>
                          </div>
                        ))}
                        {selectedReport.findings.length > 5 && (
                          <div className="text-xs text-muted-foreground">
                            ... and {selectedReport.findings.length - 5} more findings
                          </div>
                        )}
                      </div>
                    </section>

                    <section>
                      <h2 className="text-base sm:text-lg font-semibold text-foreground mb-2">Recommendations</h2>
                      <ul className="list-disc list-inside text-xs sm:text-sm text-muted-foreground space-y-1">
                        {selectedReport.recommendations.slice(0, 3).map((rec, index) => (
                          <li key={index}>{rec.title}</li>
                        ))}
                      </ul>
                    </section>
                  </div>
                </div>
              </CardContent>
            </Card>
          )}
        </TabsContent>
      </Tabs>
    </div>
  )
}
