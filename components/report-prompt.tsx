"use client"

import { useState } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Badge } from "@/components/ui/badge"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { 
  FileText, 
  Save, 
  X, 
  CheckCircle, 
  AlertTriangle,
  Info,
  Globe,
  Network,
  Search,
  Zap,
  AlertCircle
} from "lucide-react"

interface ScanResult {
  scan_type: string
  target: string
  results: any
  scan_id: string
  timestamp: string
  status: string
}

interface ReportPromptProps {
  scanResult: ScanResult
  isOpen: boolean
  onClose: () => void
  onSave: (reportData: any) => void
}

export default function ReportPrompt({ scanResult, isOpen, onClose, onSave }: ReportPromptProps) {
  const [reportTitle, setReportTitle] = useState("")
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState("")
  const [success, setSuccess] = useState("")

  if (!isOpen) return null

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
        return <AlertCircle className="h-4 w-4" />
      default:
        return <FileText className="h-4 w-4" />
    }
  }

  const getScanTypeName = (type: string) => {
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

  const calculateSeverity = () => {
    const { scan_type, results } = scanResult
    
    if (scan_type === 'vulnerability_scan') {
      const critical = results?.critical_vulnerabilities?.length || 0
      const high = results?.high_vulnerabilities?.length || 0
      const medium = results?.medium_vulnerabilities?.length || 0
      const low = results?.low_vulnerabilities?.length || 0
      
      if (critical > 0) return 'Critical'
      if (high > 0) return 'High'
      if (medium > 0) return 'Medium'
      return 'Low'
    }
    
    if (scan_type === 'port_scan') {
      const open_ports = results?.open_ports?.length || 0
      if (open_ports > 10) return 'High'
      if (open_ports > 5) return 'Medium'
      return 'Low'
    }
    
    if (scan_type === 'subdomain') {
      const subdomains = results?.subdomains?.length || 0
      if (subdomains > 20) return 'Medium'
      return 'Low'
    }
    
    return 'Low'
  }

  const getFindingsCount = () => {
    const { scan_type, results } = scanResult
    
    if (scan_type === 'vulnerability_scan') {
      return (
        (results?.critical_vulnerabilities?.length || 0) +
        (results?.high_vulnerabilities?.length || 0) +
        (results?.medium_vulnerabilities?.length || 0) +
        (results?.low_vulnerabilities?.length || 0)
      )
    }
    
    if (scan_type === 'port_scan') {
      return results?.open_ports?.length || 0
    }
    
    if (scan_type === 'subdomain') {
      return results?.subdomains?.length || 0
    }
    
    if (scan_type === 'dns') {
      return (
        (results?.a_records?.length || 0) +
        (results?.aaaa_records?.length || 0) +
        (results?.mx_records?.length || 0) +
        (results?.ns_records?.length || 0) +
        (results?.txt_records?.length || 0)
      )
    }
    
    return 1
  }

  const generateDefaultTitle = () => {
    const scanTypeName = getScanTypeName(scanResult.scan_type)
    const target = scanResult.target
    const findingsCount = getFindingsCount()
    
    return `${scanTypeName} Report - ${target} (${findingsCount} findings)`
  }

  const handleSaveReport = async () => {
    if (!reportTitle.trim()) {
      setError("Please enter a report title")
      return
    }

    try {
      setSaving(true)
      setError("")
      
      const reportData = {
        scan_type: scanResult.scan_type,
        target: scanResult.target,
        results: scanResult.results,
        scan_id: scanResult.scan_id,
        title: reportTitle,
        severity: calculateSeverity(),
        findings_count: getFindingsCount()
      }
      
      const response = await fetch('/api/reports/save-individual', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(reportData),
      })
      
      const data = await response.json()
      
      if (data.success) {
        setSuccess('Report saved successfully!')
        onSave(reportData)
        setTimeout(() => {
          onClose()
        }, 1500)
      } else {
        setError(data.error || 'Failed to save report')
      }
    } catch (error) {
      console.error('Error saving report:', error)
      setError('Failed to save report')
    } finally {
      setSaving(false)
    }
  }

  const handleSkip = () => {
    onClose()
  }

  // Set default title when component opens
  if (!reportTitle && isOpen) {
    setReportTitle(generateDefaultTitle())
  }

  const severity = calculateSeverity()
  const findingsCount = getFindingsCount()

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
      <Card className="w-full max-w-md bg-card border-border">
        <CardHeader>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              {getScanTypeIcon(scanResult.scan_type)}
              <CardTitle className="text-lg">Save Scan Results</CardTitle>
            </div>
            <Button
              variant="ghost"
              size="sm"
              onClick={handleSkip}
              className="text-muted-foreground hover:text-foreground"
            >
              <X className="h-4 w-4" />
            </Button>
          </div>
          <CardDescription>
            Would you like to save the {getScanTypeName(scanResult.scan_type)} results as a report?
          </CardDescription>
        </CardHeader>
        
        <CardContent className="space-y-4">
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

          {/* Scan Summary */}
          <div className="p-3 bg-secondary rounded-lg border border-border">
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center gap-2">
                {getScanTypeIcon(scanResult.scan_type)}
                <span className="font-medium">{getScanTypeName(scanResult.scan_type)}</span>
              </div>
              <Badge className={getSeverityColor(severity)}>{severity}</Badge>
            </div>
            
            <div className="space-y-1 text-sm">
              <div className="flex justify-between">
                <span className="text-muted-foreground">Target:</span>
                <span className="font-medium">{scanResult.target}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Findings:</span>
                <span className="font-medium">{findingsCount}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Status:</span>
                <span className="font-medium capitalize">{scanResult.status}</span>
              </div>
            </div>
          </div>

          {/* Report Title Input */}
          <div className="space-y-2">
            <Label htmlFor="report-title" className="text-sm font-medium">
              Report Title
            </Label>
            <Input
              id="report-title"
              value={reportTitle}
              onChange={(e) => setReportTitle(e.target.value)}
              placeholder="Enter report title"
              className="bg-secondary border-border"
            />
          </div>

          {/* Action Buttons */}
          <div className="flex gap-2 pt-2">
            <Button
              onClick={handleSaveReport}
              disabled={saving || !reportTitle.trim()}
              className="flex-1 bg-green-600 hover:bg-green-700"
            >
              <Save className="h-4 w-4 mr-2" />
              {saving ? 'Saving...' : 'Save Report'}
            </Button>
            <Button
              onClick={handleSkip}
              variant="outline"
              className="flex-1"
            >
              Skip
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  )
} 