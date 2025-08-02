"use client"

import { useState, useEffect } from "react"
import { useBackgroundScans } from "@/hooks/useBackgroundScans"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import NmapDetection from "@/components/nmap-detection"
import BasicPortScanner from "@/components/basic-port-scanner"
import { useReportPromptContext } from "@/components/report-prompt-provider"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Badge } from "@/components/ui/badge"
import { Progress } from "@/components/ui/progress"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Separator } from "@/components/ui/separator"
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible"
import { Switch } from "@/components/ui/switch"
import { 
  Scan, 
  Shield, 
  AlertTriangle, 
  Loader2, 
  X, 
  Play, 
  Square, 
  Target, 
  Clock, 
  Zap, 
  Network, 
  Search,
  FileText,
  Download,
  Globe,
  Eye,
  EyeOff,
  ChevronDown,
  ChevronUp,
  Filter,
  Check,
  Save,
  RotateCcw,
  Lock,
  Unlock,
  Settings,
  History,
  Activity,
  Server,
  Monitor
} from "lucide-react"

// Types
interface ScanResult {
  id: string
  type: 'port_scan' | 'vulnerability_scan' | 'comprehensive_scan'
  target: string
  scan_type: string
  status: 'running' | 'completed' | 'failed' | 'cancelled'
  progress: number
  start_time: string
  end_time?: string
  results?: any
  summary?: any
}

interface AdvancedOptions {
  portRange: string
  scanSpeed: string
  serviceDetection: boolean
  osDetection: boolean
  scriptScan: boolean
  aggressive: boolean
  zapScanType: string
  zapScanLevel: string
  zapIncludeContext: boolean
  zapCustomHeaders: string
}

interface OptionPreset {
  name: string
  description: string
  options: AdvancedOptions
  icon: string
}

// Simplified scan presets for basic scans
const SCAN_PRESETS = {
  port: [
    {
      name: "Basic Port Scan",
      description: "Standard port scan with service and OS detection",
      icon: "🔍",
      options: {
        portRange: "1-1000",
        scanSpeed: "normal",
        serviceDetection: true,
        osDetection: true,
        scriptScan: false,
        aggressive: false,
        zapScanType: "spider",
        zapScanLevel: "low",
        zapIncludeContext: false,
        zapCustomHeaders: ""
      }
    }
  ],
  vulnerability: [
    {
      name: "Full Vulnerability Scan",
      description: "Comprehensive vulnerability assessment with ZAP",
      icon: "🛡️",
      options: {
        portRange: "1-1000",
        scanSpeed: "normal",
        serviceDetection: true,
        osDetection: false,
        scriptScan: false,
        aggressive: false,
        zapScanType: "active",
        zapScanLevel: "medium",
        zapIncludeContext: true,
        zapCustomHeaders: ""
      }
    }
  ],
  comprehensive: [
    {
      name: "Full Security Assessment",
      description: "Complete port scan + vulnerability assessment",
      icon: "🎯",
      options: {
        portRange: "1-1000",
        scanSpeed: "normal",
        serviceDetection: true,
        osDetection: true,
        scriptScan: false,
        aggressive: false,
        zapScanType: "active",
        zapScanLevel: "medium",
        zapIncludeContext: true,
        zapCustomHeaders: ""
      }
    }
  ]
}

// Validation functions
const validatePortRange = (portRange: string): { isValid: boolean; error?: string } => {
  if (!portRange.trim()) {
    return { isValid: false, error: "Port range is required" }
  }
  
  const portPattern = /^(\d+(-\d+)?)(,\d+(-\d+)?)*$/
  if (!portPattern.test(portRange)) {
    return { isValid: false, error: "Invalid port range format. Use: 80,443 or 1-1000" }
  }
  
  const ports = portRange.split(',').flatMap(range => {
    if (range.includes('-')) {
      const [start, end] = range.split('-').map(Number)
      if (start < 1 || end > 65535 || start > end) {
        return []
      }
      return Array.from({ length: end - start + 1 }, (_, i) => start + i)
    } else {
      const port = Number(range)
      return port >= 1 && port <= 65535 ? [port] : []
    }
  })
  
  if (ports.length === 0) {
    return { isValid: false, error: "No valid ports in range" }
  }
  
  if (ports.length > 65535) {
    return { isValid: false, error: "Port range too large (max 65,535 ports)" }
  }
  
  return { isValid: true }
}

const validateTarget = (target: string): { isValid: boolean; error?: string } => {
  if (!target.trim()) {
    return { isValid: false, error: "Target is required" }
  }
  
  // Basic IP validation
  const ipPattern = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/
  // Basic domain validation
  const domainPattern = /^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$/
  
  if (!ipPattern.test(target) && !domainPattern.test(target)) {
    return { isValid: false, error: "Invalid target format. Use IP address or domain name" }
  }
  
  return { isValid: true }
}

export default function ScanningPage() {
  const { startScan: startBackgroundScan, activeScans, cancelScan: cancelBackgroundScan, removeScan } = useBackgroundScans()
  const { showReportPrompt } = useReportPromptContext()
  const [target, setTarget] = useState("")

  const [scanMode, setScanMode] = useState<"port" | "vulnerability" | "comprehensive">("port")
  const [loading, setLoading] = useState(false)
  const [progress, setProgress] = useState(0)
  const [currentScan, setCurrentScan] = useState<ScanResult | null>(null)
  const [error, setError] = useState("")
  const [validationErrors, setValidationErrors] = useState<{[key: string]: string}>({})
  const [scanHistory, setScanHistory] = useState<ScanResult[]>([])
  const [selectedScan, setSelectedScan] = useState<ScanResult | null>(null)
  const [selectedPreset, setSelectedPreset] = useState<string>("")
  const [useBasicScanner, setUseBasicScanner] = useState(false)
  const [nmapAvailable, setNmapAvailable] = useState(false)
  const [showResults, setShowResults] = useState(false)
  const [reportPromptShown, setReportPromptShown] = useState<{[key: string]: boolean}>({})
  // Default options
  const defaultOptions: AdvancedOptions = {
    portRange: "1-1000",
    scanSpeed: "normal",
    serviceDetection: true,
    osDetection: false,
    scriptScan: false,
    aggressive: false,
    zapScanType: "spider",
    zapScanLevel: "low",
    zapIncludeContext: false,
    zapCustomHeaders: ""
  }

  const [advancedOptions, setAdvancedOptions] = useState<AdvancedOptions>(defaultOptions)
  const [filterStatus, setFilterStatus] = useState<string>("all")
  const [searchTerm, setSearchTerm] = useState("")

  // Load scan history and advanced options from localStorage
  useEffect(() => {
    const savedHistory = localStorage.getItem('scanHistory')
    const savedOptions = localStorage.getItem('scanAdvancedOptions')
    const savedPreset = localStorage.getItem('scanSelectedPreset')
    
    if (savedHistory) {
      try {
        setScanHistory(JSON.parse(savedHistory))
      } catch (e) {
        console.error('Failed to load scan history:', e)
      }
    }
    
    if (savedOptions) {
      try {
        const parsedOptions = JSON.parse(savedOptions)
        // Merge with defaults to ensure all properties exist
        setAdvancedOptions({ ...defaultOptions, ...parsedOptions })
      } catch (e) {
        console.error('Failed to load advanced options:', e)
      }
    }
    
    // Only load preset if it's valid for the current scan mode
    if (savedPreset) {
      const currentPresets = SCAN_PRESETS[scanMode as keyof typeof SCAN_PRESETS] || []
      const isValidPreset = currentPresets.some((p: any) => p.name === savedPreset)
      if (isValidPreset) {
        setSelectedPreset(savedPreset)
      }
    }
  }, [scanMode])

  // Save data to localStorage
  useEffect(() => {
    try {
      // Limit scan history to prevent localStorage quota issues
      const limitedHistory = scanHistory.slice(-20) // Keep only last 20 scans
      
      const dataToStore = JSON.stringify(limitedHistory)
      
      // Check if data size is reasonable (under 4MB to be safe)
      if (dataToStore.length > 4 * 1024 * 1024) {
        console.warn('Scan history too large, keeping only recent scans')
        // Keep only the 5 most recent scans
        const recentHistory = scanHistory.slice(-5)
        localStorage.setItem('scanHistory', JSON.stringify(recentHistory))
      } else {
        localStorage.setItem('scanHistory', dataToStore)
      }
    } catch (error) {
      console.error('Failed to save scan history to localStorage:', error)
      // If localStorage is full, clear scan history and save only current scan
      try {
        localStorage.removeItem('scanHistory')
        if (selectedScan) {
          localStorage.setItem('scanHistory', JSON.stringify([selectedScan]))
        }
      } catch (clearError) {
        console.error('Failed to clear scan history from localStorage:', clearError)
      }
    }
  }, [scanHistory, selectedScan])

  useEffect(() => {
    localStorage.setItem('scanAdvancedOptions', JSON.stringify(advancedOptions))
  }, [advancedOptions])

  useEffect(() => {
    if (selectedPreset) {
      localStorage.setItem('scanSelectedPreset', selectedPreset)
    }
  }, [selectedPreset])

  // Clear selected preset when scan mode changes
  useEffect(() => {
    setSelectedPreset("")
  }, [scanMode])

  // Apply preset
  const applyPreset = (presetName: string) => {
    const currentPresets = SCAN_PRESETS[scanMode as keyof typeof SCAN_PRESETS] || []
    const preset = currentPresets.find((p: any) => p.name === presetName)
    if (preset) {
      setAdvancedOptions(preset.options)
      setSelectedPreset(presetName)
      setValidationErrors({})
      setError("")
    }
  }

  // Reset to default options
  const resetOptions = () => {
    setAdvancedOptions(defaultOptions)
    setSelectedPreset("")
    setValidationErrors({})
    setError("")
  }

  // Clear all localStorage data
  const clearAllData = () => {
    try {
      localStorage.removeItem('scanHistory')
      localStorage.removeItem('scanAdvancedOptions')
      localStorage.removeItem('scanSelectedPreset')
      localStorage.removeItem('backgroundScans')
      setScanHistory([])
      setSelectedScan(null)
      setAdvancedOptions(defaultOptions)
      setSelectedPreset("")
      console.log('All scan data cleared from localStorage')
    } catch (error) {
      console.error('Failed to clear data:', error)
    }
  }

  const handleUseBasicScanner = () => {
    setUseBasicScanner(true)
  }

  const handleNmapAvailable = () => {
    setNmapAvailable(true)
    setUseBasicScanner(false)
  }

  const handleBasicScanComplete = (results: any) => {
    const scanResult: ScanResult = {
      id: `basic_scan_${Date.now()}`,
      type: 'port_scan',
      target: results.target,
      scan_type: 'basic_port_scan',
      status: 'completed',
      progress: 100,
      start_time: new Date().toISOString(),
      end_time: new Date().toISOString(),
      results: results,
      summary: results.summary
    }
    
    setCurrentScan(scanResult)
    setScanHistory(prev => [scanResult, ...prev])
    setShowResults(true)
    
    // Switch back to main scanning interface to show results
    setUseBasicScanner(false)
    
    // Show report prompt after scan completion
    setTimeout(() => {
      if (!reportPromptShown[scanResult.id]) {
        setReportPromptShown(prev => ({ ...prev, [scanResult.id]: true }))
        showReportPrompt({
          scan_type: scanResult.scan_type,
          target: scanResult.target,
          results: scanResult.results,
          scan_id: scanResult.id,
          timestamp: scanResult.start_time,
          status: scanResult.status
        })
      }
    }, 1000) // Small delay to ensure UI is updated
  }

  // Validate all inputs
  const validateInputs = (): boolean => {
    const errors: {[key: string]: string} = {}
    
    // Validate target
    const targetValidation = validateTarget(target)
    if (!targetValidation.isValid) {
      errors.target = targetValidation.error!
    }
    
    // Validate port range
    const portValidation = validatePortRange(advancedOptions.portRange)
    if (!portValidation.isValid) {
      errors.portRange = portValidation.error!
    }
    
    // Validate ZAP custom headers (if provided)
    if (advancedOptions.zapCustomHeaders.trim()) {
      try {
        JSON.parse(advancedOptions.zapCustomHeaders)
      } catch {
        errors.zapCustomHeaders = "Custom headers must be valid JSON"
      }
    }
    
    setValidationErrors(errors)
    return Object.keys(errors).length === 0
  }

  // Sync with background scans
  useEffect(() => {
    const runningBackgroundScan = activeScans.find(scan => 
      scan.status === 'running' && 
      (scan.scanType === 'port_scan' || scan.scanType === 'vulnerability_scan')
    )
    
    if (runningBackgroundScan && !currentScan && 
        (runningBackgroundScan.scanType === 'port_scan' || runningBackgroundScan.scanType === 'vulnerability_scan')) {
      setCurrentScan({
        id: runningBackgroundScan.scanId,
        type: runningBackgroundScan.scanType as 'port_scan' | 'vulnerability_scan',
        target: runningBackgroundScan.target,
        scan_type: runningBackgroundScan.scan_type || 'basic',
        status: (runningBackgroundScan.status === 'error' ? 'failed' : runningBackgroundScan.status) as 'running' | 'completed' | 'failed' | 'cancelled',
        progress: runningBackgroundScan.progress,
        start_time: new Date(runningBackgroundScan.startTime).toISOString()
      })
      setLoading(true)
      setProgress(runningBackgroundScan.progress)
    }
  }, [activeScans, currentScan])

  // Poll for scan progress
  useEffect(() => {
    if (!currentScan || currentScan.status !== "running") return

    const interval = setInterval(async () => {
      try {
        // Use the correct endpoint based on scan type
        let endpoint = ''
        if (currentScan.type === 'port_scan') {
          endpoint = `http://localhost:8000/api/scan/nmap/status/${currentScan.id}/`
        } else if (currentScan.type === 'vulnerability_scan') {
          endpoint = `http://localhost:8000/api/scan/zap/status/${currentScan.id}/`
        } else {
          endpoint = `http://localhost:8000/api/recon/progress/${currentScan.id}/`
        }
        
        const response = await fetch(endpoint)
        const data = await response.json()
        
        if (data.progress !== undefined) {
          setProgress(data.progress)
          setCurrentScan(prev => prev ? { ...prev, progress: data.progress } : null)
        }
        
        // Handle completed scan
        if (data.status === 'completed' && data.results) {
          const completedScan = {
            ...currentScan,
            status: "completed" as const,
            progress: 100,
            end_time: new Date().toISOString(),
            results: data.results,
            summary: generateSummary(data.results)
          }
          
          setCurrentScan(null)
          setSelectedScan(completedScan)
          setScanHistory(prev => [completedScan, ...prev])
          setLoading(false)
          clearInterval(interval)
          
          // Show report prompt after scan completion
          setTimeout(() => {
            if (!reportPromptShown[completedScan.id]) {
              setReportPromptShown(prev => ({ ...prev, [completedScan.id]: true }))
              showReportPrompt({
                scan_type: completedScan.scan_type,
                target: completedScan.target,
                results: completedScan.results,
                scan_id: completedScan.id,
                timestamp: completedScan.start_time,
                status: completedScan.status
              })
            }
          }, 1000) // Small delay to ensure UI is updated
        }
        
        // Handle failed scan
        if (data.status === 'failed') {
          const failedScan = {
            ...currentScan,
            status: "failed" as const,
            progress: 0,
            end_time: new Date().toISOString(),
            error: data.error || 'Scan failed'
          }
          
          setCurrentScan(null)
          setSelectedScan(failedScan)
          setScanHistory(prev => [failedScan, ...prev])
          setLoading(false)
          clearInterval(interval)
        }
      } catch (error) {
        console.error("Error polling scan progress:", error)
      }
    }, 1000)

    return () => clearInterval(interval)
  }, [currentScan])

  const generateSummary = (results: any) => {
    if (results.type === "port_scan") {
      return {
        open_ports: results.open_ports,
        services: results.services,
        os_info: results.os_info
      }
    } else if (results.type === "vulnerability_scan") {
      return {
        total_vulnerabilities: results.total_vulnerabilities,
        critical_vulnerabilities: results.critical_vulnerabilities,
        high_vulnerabilities: results.high_vulnerabilities,
        medium_vulnerabilities: results.medium_vulnerabilities,
        low_vulnerabilities: results.low_vulnerabilities
      }
    }
    return {}
  }

  const startScan = async () => {
    // Clear previous errors
    setError("")
    setValidationErrors({})
    
    // Prevent multiple rapid clicks
    if (loading) {
      return
    }
    
    // Check if Nmap is available for advanced scanning
    if (!nmapAvailable) {
      setError("Nmap is not available. Click 'Use Basic Scanner Instead' below to scan ports without Nmap, or install Nmap for advanced features.")
      return
    }

    // Set loading state early
    setLoading(true)

    // Additional safety check - verify Nmap is actually available before proceeding
    try {
      const response = await fetch('http://localhost:8000/api/scan/check-nmap/', {
        method: 'GET',
        headers: { 'Content-Type': 'application/json' },
      })
      
      const data = await response.json()
      
      if (!data.success || !data.available) {
        setError("Nmap verification failed. Click 'Use Basic Scanner Instead' below to scan ports without Nmap, or install Nmap for advanced features.")
        setNmapAvailable(false)
        setLoading(false)
        return
      }
    } catch (error) {
      console.error('Error verifying Nmap availability:', error)
      setError("Unable to verify Nmap availability. Click 'Use Basic Scanner Instead' below to scan ports without Nmap, or install Nmap for advanced features.")
      setNmapAvailable(false)
      setLoading(false)
      return
    }
    
    // Validate inputs
    if (!validateInputs()) {
      setError("Please fix the validation errors before starting the scan")
      return
    }

    const scanId = `scan_${Date.now()}`
    let scanTypeValue: 'port_scan' | 'vulnerability_scan' | 'comprehensive_scan'
    let scanTypeConfig: string
    let endpoint: string

    if (scanMode === "port") {
      scanTypeValue = "port_scan"
      scanTypeConfig = "basic"
      endpoint = "port"
    } else if (scanMode === "vulnerability") {
      scanTypeValue = "vulnerability_scan"
      scanTypeConfig = "full"
      endpoint = "vulnerability"
    } else {
      // Comprehensive scan
      scanTypeValue = "comprehensive_scan"
      scanTypeConfig = "full"
      endpoint = "comprehensive"
    }

    // Start scan in background context
    startBackgroundScan({
      scanId: scanId,
      target: target,
      scanType: scanTypeValue,
      scan_type: scanTypeConfig
    })

    setCurrentScan({
      id: scanId,
      type: scanTypeValue,
      target: target,
      scan_type: scanTypeConfig,
      status: "running",
      progress: 0,
      start_time: new Date().toISOString()
    })
    setProgress(0)

    try {
      const response = await fetch(`http://localhost:8000/api/scan/${endpoint}/`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target: target,
          scan_type: scanTypeConfig,
          options: advancedOptions
        }),
      })

      const data = await response.json()

      if (data.scan_id) {
        // Update the scan ID in both currentScan and background scans
        const updatedScanId = data.scan_id
        setCurrentScan(prev => prev ? { ...prev, id: updatedScanId } : null)
        
        // Update the background scan with the correct scan ID
        removeScan(scanId)
        startBackgroundScan({
          scanId: updatedScanId,
          target: target,
          scanType: scanTypeValue,
          scan_type: scanTypeConfig
        })
        
        console.log(`${scanMode} scan started:`, data)
      } else {
        throw new Error(data.error || `Failed to start ${scanMode} scan`)
      }
    } catch (error) {
      console.error(`${scanMode} scan error:`, error)
      setError(error instanceof Error ? error.message : `Failed to start ${scanMode} scan`)
      setLoading(false)
      setCurrentScan(null)
    }
  }

  const cancelScan = async () => {
    if (!currentScan) return

    try {
      // Cancel scan in background context
      await cancelBackgroundScan(currentScan.id)
      
      const cancelledScan = { ...currentScan, status: "cancelled" as const, end_time: new Date().toISOString() }
      setCurrentScan(null)
      setSelectedScan(cancelledScan)
      setScanHistory(prev => [cancelledScan, ...prev])
      setLoading(false)
      setProgress(0)
    } catch (error) {
      console.error("Error cancelling scan:", error)
    }
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case "running": return "bg-blue-600"
      case "completed": return "bg-green-600"
      case "failed": return "bg-red-600"
      case "cancelled": return "bg-gray-600"
      default: return "bg-gray-600"
    }
  }

  const getStatusIcon = (status: string) => {
    switch (status) {
      case "running": return <Loader2 className="h-4 w-4 animate-spin" />
      case "completed": return <Check className="h-4 w-4" />
      case "failed": return <X className="h-4 w-4" />
      case "cancelled": return <Square className="h-4 w-4" />
      default: return <Clock className="h-4 w-4" />
    }
  }

  const filteredHistory = scanHistory.filter(scan => {
    const matchesStatus = filterStatus === "all" || scan.status === filterStatus
    const matchesSearch = scan.target.toLowerCase().includes(searchTerm.toLowerCase())
    return matchesStatus && matchesSearch
  })

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold text-foreground">Security Scanning</h1>
          <p className="text-muted-foreground">Advanced port and vulnerability scanning with Nmap and ZAP integration</p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm">
            <History className="h-4 w-4 mr-2" />
            Scan History
          </Button>
          <Button variant="outline" size="sm">
            <Settings className="h-4 w-4 mr-2" />
            Settings
          </Button>
        </div>
      </div>

      {/* Nmap Detection and Basic Scanner */}
      {useBasicScanner ? (
        <BasicPortScanner onScanComplete={handleBasicScanComplete} />
      ) : (
        <NmapDetection
          onUseBasicScanner={handleUseBasicScanner}
          onNmapAvailable={handleNmapAvailable}
        >

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Unified Scan Configuration Panel */}
        <div className="lg:col-span-1 space-y-6">
          {/* Integrated Scan Configuration Card */}
          <Card className="bg-gradient-to-br from-blue-900/20 to-purple-900/20 border-blue-700/50">
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-foreground">
                <Target className="h-5 w-5 text-blue-400" />
                Scan Configuration
                {!nmapAvailable && (
                  <Badge variant="outline" className="text-orange-600 border-orange-600 text-xs">
                    Basic Mode
                  </Badge>
                )}
              </CardTitle>
              <CardDescription className="text-muted-foreground">
                {nmapAvailable 
                  ? "Configure target and scanning parameters" 
                  : "Basic scanning mode - Nmap not available"
                }
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              {/* Nmap Status Warning */}
              {!nmapAvailable && (
                <Alert className="border-orange-500 bg-orange-50 dark:bg-orange-900/20">
                  <AlertTriangle className="h-4 w-4 text-orange-500" />
                  <AlertDescription className="text-orange-700 dark:text-orange-300">
                    Nmap is not available. Advanced scanning features are disabled. Use the basic scanner for quick port detection.
                  </AlertDescription>
                </Alert>
              )}
              
              {/* Target Configuration Section */}
              <div className="space-y-4">
                
              <div className="space-y-2">
                <Label htmlFor="target" className="text-foreground">
                  Target Host/IP
                </Label>
                <div className="relative">
                  <Globe className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
                  <Input
                    id="target"
                    value={target}
                    onChange={(e) => setTarget(e.target.value)}
                    placeholder="192.168.1.1 or example.com"
                    className="pl-10 bg-secondary/50 border-border"
                  />
                </div>
                  {validationErrors.target && (
                    <p className="text-xs text-red-400 mt-1">{validationErrors.target}</p>
                  )}
              </div>

              <div className="space-y-2">
                <Label className="text-foreground">Scan Mode</Label>
                <div className="grid grid-cols-3 gap-2">
                  <Button
                    variant={scanMode === "port" ? "default" : "outline"}
                    size="sm"
                    onClick={() => setScanMode("port")}
                    className="text-xs"
                  >
                    <Network className="h-3 w-3 mr-1" />
                    Port
                  </Button>
                  <Button
                    variant={scanMode === "vulnerability" ? "default" : "outline"}
                    size="sm"
                    onClick={() => setScanMode("vulnerability")}
                    className="text-xs"
                  >
                    <Shield className="h-3 w-3 mr-1" />
                    Vuln
                  </Button>
                  <Button
                    variant={scanMode === "comprehensive" ? "default" : "outline"}
                    size="sm"
                    onClick={() => setScanMode("comprehensive")}
                    className="text-xs"
                  >
                    <Zap className="h-3 w-3 mr-1" />
                    Full
                  </Button>
                </div>
              </div>

              <div className="space-y-2">
                <Label className="text-foreground">Scan Preset</Label>
                <Select 
                  value={selectedPreset} 
                  onValueChange={applyPreset}
                >
                  <SelectTrigger className="bg-secondary/50 border-border">
                    <SelectValue placeholder="Select scan type" />
                  </SelectTrigger>
                  <SelectContent>
                    {SCAN_PRESETS[scanMode as keyof typeof SCAN_PRESETS]?.map((preset: any) => (
                      <SelectItem key={preset.name} value={preset.name}>
                        <div className="flex items-center gap-2">
                          <span className="text-lg">{preset.icon}</span>
                          <div className="flex flex-col">
                            <span className="font-medium">{preset.name}</span>
                            <span className="text-xs text-muted-foreground">{preset.description}</span>
                          </div>
                        </div>
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>


              </div>

              <Separator className="bg-border/50" />

              {/* Advanced Options Section */}
              <div className="space-y-4">

                {/* Nmap Options - Only show for port scans */}
                {scanMode === "port" && (
                  <div className="space-y-3">

              <div className="space-y-2">
                      <Label className="text-foreground text-sm">Port Range</Label>
                      <Input
                        value={advancedOptions.portRange}
                        onChange={(e) => setAdvancedOptions(prev => ({ ...prev, portRange: e.target.value }))}
                        placeholder="1-1000"
                        className="bg-secondary/50 border-border"
                      />
                      {validationErrors.portRange && (
                        <p className="text-xs text-red-400 mt-1">{validationErrors.portRange}</p>
                      )}
                    </div>

                    <div className="space-y-2">
                      <Label className="text-foreground text-sm">Scan Speed</Label>
                      <Select 
                        value={advancedOptions.scanSpeed} 
                        onValueChange={(value) => setAdvancedOptions(prev => ({ ...prev, scanSpeed: value }))}
                      >
                  <SelectTrigger className="bg-secondary/50 border-border">
                          <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                          <SelectItem value="slow">Slow (T0)</SelectItem>
                          <SelectItem value="normal">Normal (T3)</SelectItem>
                          <SelectItem value="fast">Fast (T4)</SelectItem>
                          <SelectItem value="aggressive">Aggressive (T5)</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>

                    <div className="space-y-2">
                      <Label className="text-foreground text-sm">Detection Options</Label>
                      <div className="space-y-3">
                        <div className="flex items-center justify-between">
                          <span className="text-sm text-muted-foreground">Service Detection</span>
                          <Switch
                            checked={advancedOptions.serviceDetection}
                            onCheckedChange={(checked) => setAdvancedOptions(prev => ({ ...prev, serviceDetection: checked }))}
                          />
                        </div>
                        <div className="flex items-center justify-between">
                          <span className="text-sm text-muted-foreground">OS Detection</span>
                          <Switch
                            checked={advancedOptions.osDetection}
                            onCheckedChange={(checked) => setAdvancedOptions(prev => ({ ...prev, osDetection: checked }))}
                          />
                        </div>
                        <div className="flex items-center justify-between">
                          <span className="text-sm text-muted-foreground">Script Scan</span>
                          <Switch
                            checked={advancedOptions.scriptScan}
                            onCheckedChange={(checked) => setAdvancedOptions(prev => ({ ...prev, scriptScan: checked }))}
                          />
                        </div>
                      </div>
                    </div>
                  </div>
                )}

                {/* ZAP Options - Only show for vulnerability scans */}
                {scanMode === "vulnerability" && (
                  <div className="space-y-3">
                    
                    <div className="space-y-2">
                      <Label className="text-foreground text-sm">ZAP Scan Type</Label>
                      <Select 
                        value={advancedOptions.zapScanType} 
                        onValueChange={(value) => setAdvancedOptions(prev => ({ ...prev, zapScanType: value }))}
                      >
                        <SelectTrigger className="bg-secondary/50 border-border">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="spider">Spider</SelectItem>
                          <SelectItem value="active">Active</SelectItem>
                          <SelectItem value="passive">Passive</SelectItem>
                  </SelectContent>
                </Select>
              </div>

                    <div className="space-y-2">
                      <Label className="text-foreground text-sm">ZAP Scan Level</Label>
                      <Select 
                        value={advancedOptions.zapScanLevel} 
                        onValueChange={(value) => setAdvancedOptions(prev => ({ ...prev, zapScanLevel: value }))}
                      >
                        <SelectTrigger className="bg-secondary/50 border-border">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="low">Low</SelectItem>
                          <SelectItem value="medium">Medium</SelectItem>
                          <SelectItem value="high">High</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>

                    <div className="space-y-2">
                      <div className="flex items-center justify-between">
                        <Label className="text-foreground text-sm">Include Context</Label>
                        <Switch
                          checked={advancedOptions.zapIncludeContext}
                          onCheckedChange={(checked) => setAdvancedOptions(prev => ({ ...prev, zapIncludeContext: checked }))}
                        />
                      </div>
                      <p className="text-xs text-muted-foreground">
                        For active scans, include context (cookies, headers, etc.)
                      </p>
                    </div>

                    <div className="space-y-2">
                      <Label className="text-foreground text-sm">Custom Headers (JSON)</Label>
                      <Input
                        value={advancedOptions.zapCustomHeaders}
                        onChange={(e) => setAdvancedOptions(prev => ({ ...prev, zapCustomHeaders: e.target.value }))}
                        placeholder='{"User-Agent": "Mozilla/5.0 (compatible; PEN-T Scanner)"}'
                        className="bg-secondary/50 border-border"
                      />
                      {validationErrors.zapCustomHeaders && (
                        <p className="text-xs text-red-400 mt-1">{validationErrors.zapCustomHeaders}</p>
                      )}
                    </div>
                  </div>
                )}

                {/* Comprehensive Options - Show both Nmap and ZAP for full scans */}
                {scanMode === "comprehensive" && (
                  <div className="space-y-4">
                    {/* Nmap Configuration */}
                    <div className="space-y-3">
                      <div className="flex items-center gap-2">
                        <Network className="h-4 w-4 text-blue-400" />
                        <span className="text-sm font-medium text-foreground">Nmap Configuration</span>
                      </div>
                      
                      <div className="space-y-2">
                        <Label className="text-foreground text-sm">Port Range</Label>
                        <Input
                          value={advancedOptions.portRange}
                          onChange={(e) => setAdvancedOptions(prev => ({ ...prev, portRange: e.target.value }))}
                          placeholder="1-1000"
                          className="bg-secondary/50 border-border"
                        />
                        {validationErrors.portRange && (
                          <p className="text-xs text-red-400 mt-1">{validationErrors.portRange}</p>
                        )}
                      </div>

                      <div className="space-y-2">
                        <Label className="text-foreground text-sm">Scan Speed</Label>
                        <Select 
                          value={advancedOptions.scanSpeed} 
                          onValueChange={(value) => setAdvancedOptions(prev => ({ ...prev, scanSpeed: value }))}
                        >
                          <SelectTrigger className="bg-secondary/50 border-border">
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="slow">Slow (T0)</SelectItem>
                            <SelectItem value="normal">Normal (T3)</SelectItem>
                            <SelectItem value="fast">Fast (T4)</SelectItem>
                            <SelectItem value="aggressive">Aggressive (T5)</SelectItem>
                          </SelectContent>
                        </Select>
                      </div>

                      <div className="space-y-2">
                        <Label className="text-foreground text-sm">Detection Options</Label>
                        <div className="space-y-3">
                          <div className="flex items-center justify-between">
                            <span className="text-sm text-muted-foreground">Service Detection</span>
                            <Switch
                              checked={advancedOptions.serviceDetection}
                              onCheckedChange={(checked) => setAdvancedOptions(prev => ({ ...prev, serviceDetection: checked }))}
                            />
                          </div>
                          <div className="flex items-center justify-between">
                            <span className="text-sm text-muted-foreground">OS Detection</span>
                            <Switch
                              checked={advancedOptions.osDetection}
                              onCheckedChange={(checked) => setAdvancedOptions(prev => ({ ...prev, osDetection: checked }))}
                            />
                          </div>
                          <div className="flex items-center justify-between">
                            <span className="text-sm text-muted-foreground">Script Scan</span>
                            <Switch
                              checked={advancedOptions.scriptScan}
                              onCheckedChange={(checked) => setAdvancedOptions(prev => ({ ...prev, scriptScan: checked }))}
                            />
                          </div>
                        </div>
                      </div>
                    </div>

                    <Separator className="bg-border/30" />

                    {/* ZAP Configuration */}
                    <div className="space-y-3">
                      <div className="flex items-center gap-2">
                        <Shield className="h-4 w-4 text-green-400" />
                        <span className="text-sm font-medium text-foreground">ZAP Configuration</span>
                      </div>
                      
                      <div className="space-y-2">
                        <Label className="text-foreground text-sm">ZAP Scan Type</Label>
                        <Select 
                          value={advancedOptions.zapScanType} 
                          onValueChange={(value) => setAdvancedOptions(prev => ({ ...prev, zapScanType: value }))}
                        >
                          <SelectTrigger className="bg-secondary/50 border-border">
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="spider">Spider</SelectItem>
                            <SelectItem value="active">Active</SelectItem>
                            <SelectItem value="passive">Passive</SelectItem>
                          </SelectContent>
                        </Select>
                      </div>

                      <div className="space-y-2">
                        <Label className="text-foreground text-sm">ZAP Scan Level</Label>
                        <Select 
                          value={advancedOptions.zapScanLevel} 
                          onValueChange={(value) => setAdvancedOptions(prev => ({ ...prev, zapScanLevel: value }))}
                        >
                          <SelectTrigger className="bg-secondary/50 border-border">
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="low">Low</SelectItem>
                            <SelectItem value="medium">Medium</SelectItem>
                            <SelectItem value="high">High</SelectItem>
                          </SelectContent>
                        </Select>
                      </div>

                      <div className="space-y-2">
                        <div className="flex items-center justify-between">
                          <Label className="text-foreground text-sm">Include Context</Label>
                          <Switch
                            checked={advancedOptions.zapIncludeContext}
                            onCheckedChange={(checked) => setAdvancedOptions(prev => ({ ...prev, zapIncludeContext: checked }))}
                          />
                        </div>
                        <p className="text-xs text-muted-foreground">
                          For active scans, include context (cookies, headers, etc.)
                        </p>
                      </div>

                      <div className="space-y-2">
                        <Label className="text-foreground text-sm">Custom Headers (JSON)</Label>
                        <Input
                          value={advancedOptions.zapCustomHeaders}
                          onChange={(e) => setAdvancedOptions(prev => ({ ...prev, zapCustomHeaders: e.target.value }))}
                          placeholder='{"User-Agent": "Mozilla/5.0 (compatible; PEN-T Scanner)"}'
                          className="bg-secondary/50 border-border"
                        />
                        {validationErrors.zapCustomHeaders && (
                          <p className="text-xs text-red-400 mt-1">{validationErrors.zapCustomHeaders}</p>
                        )}
                      </div>
                    </div>
                  </div>
                )}
              </div>

              <Separator className="bg-border/50" />

              {/* Action Buttons */}
              <div className="space-y-3">
              {error && (
                <Alert className="bg-red-900/20 border-red-700">
                  <AlertDescription className="text-red-200">{error}</AlertDescription>
                </Alert>
              )}

                <Button
                  onClick={startScan}
                  disabled={!target || loading || !nmapAvailable}
                  className="w-full bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-700 hover:to-purple-700"
                  size="lg"
                >
                  {loading ? (
                    <Loader2 className="h-4 w-4 animate-spin mr-2" />
                  ) : (
                    <Play className="h-4 w-4 mr-2" />
                  )}
                  {!nmapAvailable 
                    ? "Nmap Not Available" 
                    : `Start ${scanMode === "port" ? "Port" : scanMode === "vulnerability" ? "Vulnerability" : "Comprehensive"} Scan`
                  }
                </Button>

                {loading && (
                  <Button
                    onClick={cancelScan}
                    variant="outline"
                    className="w-full border-red-600 text-red-600 hover:bg-red-600 hover:text-white"
                  >
                    <Square className="h-4 w-4 mr-2" />
                    Cancel Scan
                  </Button>
                )}

                {!nmapAvailable && !loading && (
                  <Button
                    onClick={handleUseBasicScanner}
                    variant="outline"
                    className="w-full border-green-600 text-green-600 hover:bg-green-600 hover:text-white"
                  >
                    <Network className="h-4 w-4 mr-2" />
                    Use Basic Scanner Instead
                  </Button>
                )}

                {/* Test Scan Button for Development */}
                {process.env.NODE_ENV === 'development' && (
                  <Button
                    onClick={() => {
                      let testScan: ScanResult
                      
                      if (scanMode === "port") {
                        testScan = {
                          id: `test_port_${Date.now()}`,
                          type: "port_scan",
                          target: "google.com",
                          scan_type: "quick",
                          status: "completed",
                          progress: 100,
                          start_time: new Date(Date.now() - 22000).toISOString(),
                          end_time: new Date().toISOString(),
                          results: {
                            type: "port_scan",
                            target: "google.com",
                            scan_type: "quick",
                            total_ports: 15,
                            open_ports: 3,
                            os_info: {
                              name: "Linux 3.2-4.9",
                              accuracy: "95",
                              line: "OS: Linux 3.2-4.9"
                            },
                            data: [
                              { port: 80, protocol: "tcp", state: "open", service: "http", version: "nginx" },
                              { port: 443, protocol: "tcp", state: "open", service: "https", version: "nginx" },
                              { port: 22, protocol: "tcp", state: "open", service: "ssh", version: "OpenSSH 8.2" },
                              { port: 21, protocol: "tcp", state: "closed", service: "ftp", version: "" },
                              { port: 25, protocol: "tcp", state: "filtered", service: "smtp", version: "" },
                              { port: 23, protocol: "tcp", state: "closed", service: "telnet", version: "" },
                              { port: 53, protocol: "tcp", state: "filtered", service: "domain", version: "" },
                              { port: 110, protocol: "tcp", state: "closed", service: "pop3", version: "" },
                              { port: 143, protocol: "tcp", state: "filtered", service: "imap", version: "" },
                              { port: 993, protocol: "tcp", state: "closed", service: "imaps", version: "" },
                              { port: 995, protocol: "tcp", state: "filtered", service: "pop3s", version: "" },
                              { port: 3306, protocol: "tcp", state: "closed", service: "mysql", version: "" },
                              { port: 3389, protocol: "tcp", state: "filtered", service: "ms-wbt-server", version: "" },
                              { port: 5432, protocol: "tcp", state: "closed", service: "postgresql", version: "" },
                              { port: 8080, protocol: "tcp", state: "filtered", service: "http-proxy", version: "" }
                            ]
                          }
                        }
                      } else if (scanMode === "vulnerability") {
                        testScan = {
                          id: `test_vuln_${Date.now()}`,
                          type: "vulnerability_scan",
                          target: "google.com",
                          scan_type: "active",
                          status: "completed",
                          progress: 100,
                          start_time: new Date(Date.now() - 45000).toISOString(),
                          end_time: new Date().toISOString(),
                          results: {
                            type: "vulnerability_scan",
                            target: "google.com",
                            scan_type: "active",
                            total_vulnerabilities: 8,
                            critical_vulnerabilities: 1,
                            high_vulnerabilities: 2,
                            medium_vulnerabilities: 3,
                            low_vulnerabilities: 2,
                            data: [
                              {
                                id: "CVE-2023-1234",
                                name: "SQL Injection Vulnerability",
                                severity: "critical",
                                description: "SQL injection vulnerability in login form",
                                solution: "Use parameterized queries",
                                references: ["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-1234"]
                              },
                              {
                                id: "CVE-2023-5678",
                                name: "Cross-Site Scripting (XSS)",
                                severity: "high",
                                description: "Reflected XSS in search functionality",
                                solution: "Implement proper input validation and output encoding",
                                references: ["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-5678"]
                              },
                              {
                                id: "CVE-2023-9012",
                                name: "Outdated SSL/TLS Configuration",
                                severity: "high",
                                description: "Server supports weak SSL/TLS protocols",
                                solution: "Disable SSLv3 and TLS 1.0/1.1",
                                references: ["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-9012"]
                              },
                              {
                                id: "CVE-2023-3456",
                                name: "Information Disclosure",
                                severity: "medium",
                                description: "Server reveals version information in headers",
                                solution: "Remove or modify server headers",
                                references: ["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-3456"]
                              },
                              {
                                id: "CVE-2023-7890",
                                name: "Missing Security Headers",
                                severity: "medium",
                                description: "Missing Content-Security-Policy header",
                                solution: "Implement security headers",
                                references: ["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-7890"]
                              },
                              {
                                id: "CVE-2023-2345",
                                name: "Directory Listing Enabled",
                                severity: "medium",
                                description: "Directory listing is enabled on web server",
                                solution: "Disable directory listing",
                                references: ["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-2345"]
                              },
                              {
                                id: "CVE-2023-6789",
                                name: "Weak Password Policy",
                                severity: "low",
                                description: "No password complexity requirements",
                                solution: "Implement strong password policy",
                                references: ["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-6789"]
                              },
                              {
                                id: "CVE-2023-0123",
                                name: "Missing HTTP Security Headers",
                                severity: "low",
                                description: "Missing X-Frame-Options header",
                                solution: "Add security headers",
                                references: ["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-0123"]
                              }
                            ]
                          }
                        }
                      } else {
                        // Comprehensive scan - includes both port and vulnerability results
                        testScan = {
                          id: `test_comp_${Date.now()}`,
                          type: "comprehensive_scan", // New type for comprehensive scans
                          target: "google.com",
                          scan_type: "comprehensive",
                          status: "completed",
                          progress: 100,
                          start_time: new Date(Date.now() - 60000).toISOString(),
                          end_time: new Date().toISOString(),
                          results: {
                            type: "comprehensive_scan",
                            target: "google.com",
                            scan_type: "comprehensive",
                            port_scan: {
                              type: "port_scan",
                              total_ports: 20,
                              open_ports: 5,
                              os_info: {
                                name: "Linux 4.19-5.10",
                                accuracy: "98",
                                line: "OS: Linux 4.19-5.10"
                              },
                              data: [
                                { port: 80, protocol: "tcp", state: "open", service: "http", version: "nginx" },
                                { port: 443, protocol: "tcp", state: "open", service: "https", version: "nginx" },
                                { port: 22, protocol: "tcp", state: "open", service: "ssh", version: "OpenSSH 8.2" },
                                { port: 8080, protocol: "tcp", state: "open", service: "http-proxy", version: "nginx" },
                                { port: 8443, protocol: "tcp", state: "open", service: "https-alt", version: "nginx" },
                                { port: 21, protocol: "tcp", state: "closed", service: "ftp", version: "" },
                                { port: 25, protocol: "tcp", state: "filtered", service: "smtp", version: "" },
                                { port: 23, protocol: "tcp", state: "closed", service: "telnet", version: "" },
                                { port: 53, protocol: "tcp", state: "filtered", service: "domain", version: "" },
                                { port: 110, protocol: "tcp", state: "closed", service: "pop3", version: "" },
                                { port: 143, protocol: "tcp", state: "filtered", service: "imap", version: "" },
                                { port: 993, protocol: "tcp", state: "closed", service: "imaps", version: "" },
                                { port: 995, protocol: "tcp", state: "filtered", service: "pop3s", version: "" },
                                { port: 3306, protocol: "tcp", state: "closed", service: "mysql", version: "" },
                                { port: 3389, protocol: "tcp", state: "filtered", service: "ms-wbt-server", version: "" },
                                { port: 5432, protocol: "tcp", state: "closed", service: "postgresql", version: "" },
                                { port: 27017, protocol: "tcp", state: "closed", service: "mongodb", version: "" },
                                { port: 6379, protocol: "tcp", state: "closed", service: "redis", version: "" },
                                { port: 9200, protocol: "tcp", state: "closed", service: "elasticsearch", version: "" },
                                { port: 11211, protocol: "tcp", state: "closed", service: "memcache", version: "" }
                              ]
                            },
                            vulnerability_scan: {
                              type: "vulnerability_scan",
                              total_vulnerabilities: 8,
                              critical_vulnerabilities: 1,
                              high_vulnerabilities: 2,
                              medium_vulnerabilities: 3,
                              low_vulnerabilities: 2,
                              data: [
                                {
                                  id: "CVE-2023-1234",
                                  name: "SQL Injection Vulnerability",
                                  severity: "critical",
                                  description: "SQL injection vulnerability in login form",
                                  solution: "Use parameterized queries",
                                  references: ["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-1234"]
                                },
                                {
                                  id: "CVE-2023-5678",
                                  name: "Cross-Site Scripting (XSS)",
                                  severity: "high",
                                  description: "Reflected XSS in search functionality",
                                  solution: "Implement proper input validation and output encoding",
                                  references: ["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-5678"]
                                },
                                {
                                  id: "CVE-2023-9012",
                                  name: "Outdated SSL/TLS Configuration",
                                  severity: "high",
                                  description: "Server supports weak SSL/TLS protocols",
                                  solution: "Disable SSLv3 and TLS 1.0/1.1",
                                  references: ["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-9012"]
                                },
                                {
                                  id: "CVE-2023-3456",
                                  name: "Information Disclosure",
                                  severity: "medium",
                                  description: "Server reveals version information in headers",
                                  solution: "Remove or modify server headers",
                                  references: ["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-3456"]
                                },
                                {
                                  id: "CVE-2023-7890",
                                  name: "Missing Security Headers",
                                  severity: "medium",
                                  description: "Missing Content-Security-Policy header",
                                  solution: "Implement security headers",
                                  references: ["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-7890"]
                                },
                                {
                                  id: "CVE-2023-2345",
                                  name: "Directory Listing Enabled",
                                  severity: "medium",
                                  description: "Directory listing is enabled on web server",
                                  solution: "Disable directory listing",
                                  references: ["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-2345"]
                                },
                                {
                                  id: "CVE-2023-6789",
                                  name: "Weak Password Policy",
                                  severity: "low",
                                  description: "No password complexity requirements",
                                  solution: "Implement strong password policy",
                                  references: ["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-6789"]
                                },
                                {
                                  id: "CVE-2023-0123",
                                  name: "Missing HTTP Security Headers",
                                  severity: "low",
                                  description: "Missing X-Frame-Options header",
                                  solution: "Add security headers",
                                  references: ["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-0123"]
                                }
                              ]
                            }
                          }
                        }
                      }
                      
                      setSelectedScan(testScan)
                      setScanHistory(prev => [testScan, ...prev])
                    }}
                    variant="outline"
                    className="w-full border-blue-600 text-blue-600 hover:bg-blue-600 hover:text-white"
                  >
                    <Play className="h-4 w-4 mr-2" />
                    Test {scanMode === "port" ? "Port" : scanMode === "vulnerability" ? "Vulnerability" : "Comprehensive"} Scan
                  </Button>
                )}
              </div>
            </CardContent>
          </Card>



          {/* Current Scan Status */}
          {currentScan && (
            <Card className="bg-blue-900/20 border-blue-700/50">
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-foreground">
                  <Activity className="h-5 w-5 text-blue-400" />
                  Current Scan
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-muted-foreground">Progress</span>
                    <span className="text-sm font-medium">{progress}%</span>
                  </div>
                  <Progress value={progress} className="bg-blue-900/30" />
                </div>
                
                <div className="space-y-2 text-sm">
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Target:</span>
                    <span className="font-medium">{currentScan.target}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Type:</span>
                    <span className="font-medium capitalize">{currentScan.scan_type}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Started:</span>
                    <span className="font-medium">{new Date(currentScan.start_time).toLocaleTimeString()}</span>
                  </div>
                </div>
              </CardContent>
            </Card>
          )}
        </div>

        {/* Results Panel */}
        <div className="lg:col-span-2 space-y-6">
          <Tabs defaultValue="results" className="w-full">
            <TabsList className="grid w-full grid-cols-3">
              <TabsTrigger value="results">Scan Results</TabsTrigger>
              <TabsTrigger value="history">Scan History</TabsTrigger>
              <TabsTrigger value="analytics">Analytics</TabsTrigger>
            </TabsList>

            <TabsContent value="results" className="space-y-4">
              {currentScan && currentScan.status === 'completed' ? (
                <ScanResultsView scan={currentScan} />
              ) : selectedScan ? (
                <ScanResultsView scan={selectedScan} />
              ) : (
                <Card className="bg-secondary/30 border-border">
                  <CardContent className="flex flex-col items-center justify-center py-12">
                    <Scan className="h-12 w-12 text-muted-foreground mb-4" />
                    <h3 className="text-lg font-medium text-foreground mb-2">No Scan Results</h3>
                    <p className="text-muted-foreground text-center">
                      Start a scan to see detailed results here
                    </p>
                  </CardContent>
                </Card>
              )}
            </TabsContent>

            <TabsContent value="history" className="space-y-4">
              <Card className="bg-secondary/30 border-border">
                <CardHeader>
                  <CardTitle className="flex items-center justify-between">
                    <span>Scan History</span>
                    <div className="flex items-center gap-2">
                      <div className="relative">
                        <Search className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
                        <Input
                          placeholder="Search targets..."
                          value={searchTerm}
                          onChange={(e) => setSearchTerm(e.target.value)}
                          className="pl-10 w-48"
                        />
                      </div>
                      <Select value={filterStatus} onValueChange={setFilterStatus}>
                        <SelectTrigger className="w-32">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="all">All</SelectItem>
                          <SelectItem value="completed">Completed</SelectItem>
                          <SelectItem value="running">Running</SelectItem>
                          <SelectItem value="failed">Failed</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2">
                    {filteredHistory.map((scan) => (
                      <div
                        key={scan.id}
                        className={`p-4 rounded-lg border cursor-pointer transition-colors ${
                          selectedScan?.id === scan.id 
                            ? "bg-blue-900/20 border-blue-700" 
                            : "bg-secondary/50 border-border hover:bg-secondary/70"
                        }`}
                        onClick={() => setSelectedScan(scan)}
                      >
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-3">
                            <Badge className={getStatusColor(scan.status)}>
                              {getStatusIcon(scan.status)}
                            </Badge>
                            <div>
                              <p className="font-medium text-foreground">{scan.target}</p>
                              <p className="text-sm text-muted-foreground">
                                {scan.type === "port_scan" ? "Port Scan" : "Vulnerability Scan"} • {scan.scan_type}
                              </p>
                            </div>
                          </div>
                          <div className="text-right">
                            <p className="text-sm text-muted-foreground">
                              {new Date(scan.start_time).toLocaleDateString()}
                            </p>
                            <p className="text-xs text-muted-foreground">
                              {new Date(scan.start_time).toLocaleTimeString()}
                            </p>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            </TabsContent>

            <TabsContent value="analytics" className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                <Card className="bg-green-900/20 border-green-700/50">
                  <CardContent className="p-4">
                    <div className="flex items-center gap-2">
                      <Server className="h-5 w-5 text-green-400" />
                      <span className="text-sm text-muted-foreground">Total Scans</span>
                    </div>
                    <p className="text-2xl font-bold text-foreground mt-2">{scanHistory.length}</p>
                  </CardContent>
                </Card>
                
                <Card className="bg-blue-900/20 border-blue-700/50">
                  <CardContent className="p-4">
                    <div className="flex items-center gap-2">
                      <Network className="h-5 w-5 text-blue-400" />
                      <span className="text-sm text-muted-foreground">Port Scans</span>
                    </div>
                    <p className="text-2xl font-bold text-foreground mt-2">
                      {scanHistory.filter(s => s.type === "port_scan").length}
                    </p>
                  </CardContent>
                </Card>
                
                <Card className="bg-red-900/20 border-red-700/50">
                  <CardContent className="p-4">
                    <div className="flex items-center gap-2">
                      <Shield className="h-5 w-5 text-red-400" />
                      <span className="text-sm text-muted-foreground">Vuln Scans</span>
                    </div>
                    <p className="text-2xl font-bold text-foreground mt-2">
                      {scanHistory.filter(s => s.type === "vulnerability_scan").length}
                    </p>
                  </CardContent>
                </Card>
                
                <Card className="bg-purple-900/20 border-purple-700/50">
                  <CardContent className="p-4">
                    <div className="flex items-center gap-2">
                      <Activity className="h-5 w-5 text-purple-400" />
                      <span className="text-sm text-muted-foreground">Comprehensive</span>
                    </div>
                    <p className="text-2xl font-bold text-foreground mt-2">
                      {scanHistory.filter(s => s.type === "comprehensive_scan").length}
                    </p>
                  </CardContent>
                </Card>
                
                <Card className="bg-green-900/20 border-green-700/50">
                  <CardContent className="p-4">
                    <div className="flex items-center gap-2">
                      <Activity className="h-5 w-5 text-green-400" />
                      <span className="text-sm text-muted-foreground">Success Rate</span>
                    </div>
                    <p className="text-2xl font-bold text-foreground mt-2">
                      {scanHistory.length > 0 
                        ? Math.round((scanHistory.filter(s => s.status === "completed").length / scanHistory.length) * 100)
                        : 0}%
                    </p>
                  </CardContent>
                </Card>
              </div>
            </TabsContent>
          </Tabs>
        </div>
      </div>
        </NmapDetection>
      )}






    </div>
  )
}

// Separate component for scan results
function ScanResultsView({ scan }: { scan: ScanResult }) {
  const [expandedSections, setExpandedSections] = useState<string[]>([])

  const toggleSection = (section: string) => {
    setExpandedSections(prev => 
      prev.includes(section) 
        ? prev.filter(s => s !== section)
        : [...prev, section]
    )
  }

  if (!scan.results) {
    return (
      <Card className="bg-secondary/30 border-border">
        <CardContent className="flex flex-col items-center justify-center py-12">
          <AlertTriangle className="h-12 w-12 text-yellow-400 mb-4" />
          <h3 className="text-lg font-medium text-foreground mb-2">Scan {scan.status}</h3>
          <p className="text-muted-foreground text-center">
            {scan.status === "cancelled" ? "Scan was cancelled" : "Scan failed to complete"}
          </p>
          <div className="mt-4 text-xs text-muted-foreground">
            <p>Scan ID: {scan.id}</p>
            <p>Type: {scan.type}</p>
            <p>Target: {scan.target}</p>
          </div>
        </CardContent>
      </Card>
    )
  }

  return (
    <div className="space-y-4">
      {/* Scan Summary */}
      <Card className="bg-gradient-to-br from-green-900/20 to-blue-900/20 border-green-700/50">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-foreground">
            <FileText className="h-5 w-5 text-green-400" />
            Scan Summary
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div>
              <p className="text-sm text-muted-foreground">Target</p>
              <p className="font-medium text-foreground">{scan.target}</p>
            </div>
            <div>
              <p className="text-sm text-muted-foreground">Scan Type</p>
              <p className="font-medium text-foreground capitalize">{scan.scan_type}</p>
            </div>
            <div>
              <p className="text-sm text-muted-foreground">Duration</p>
              <p className="font-medium text-foreground">
                {scan.end_time 
                  ? `${Math.round((new Date(scan.end_time).getTime() - new Date(scan.start_time).getTime()) / 1000)}s`
                  : "Running..."
                }
              </p>
            </div>
            <div>
              <p className="text-sm text-muted-foreground">Status</p>
              <Badge className="bg-green-600">Completed</Badge>
            </div>
          </div>
          
          {/* Additional Summary Information */}
          {scan.results && (
            <div className="mt-4 pt-4 border-t border-border">
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                {scan.results.type === "port_scan" && (
                  <>
                    <div>
                      <p className="text-sm text-muted-foreground">Total Ports</p>
                      <p className="font-medium text-foreground">
                        {scan.results.total_ports || scan.results.data?.length || scan.results.ports_scanned || 0}
                      </p>
                    </div>
                    <div>
                      <p className="text-sm text-muted-foreground">Open Ports</p>
                      <p className="font-medium text-foreground text-green-400">
                        {scan.results.open_ports?.length || scan.results.open_count || (scan.results.data?.filter((p: any) => p.state === "open")?.length || 0)}
                      </p>
                    </div>
                    <div>
                      <p className="text-sm text-muted-foreground">Closed Ports</p>
                      <p className="font-medium text-foreground text-red-400">
                        {scan.results.closed_ports?.length || scan.results.closed_count || (scan.results.data?.filter((p: any) => p.state === "closed")?.length || 0)}
                      </p>
                    </div>
                    <div>
                      <p className="text-sm text-muted-foreground">Filtered Ports</p>
                      <p className="font-medium text-foreground text-yellow-400">
                        {scan.results.filtered_ports?.length || scan.results.filtered_count || (scan.results.data?.filter((p: any) => p.state === "filtered")?.length || 0)}
                      </p>
                    </div>
                    {scan.results.os_info && Object.keys(scan.results.os_info).length > 0 && (
                      <div>
                        <p className="text-sm text-muted-foreground">OS Detected</p>
                        <p className="font-medium text-foreground text-blue-400">
                          {scan.results.os_info.name || 'Unknown'}
                        </p>
                      </div>
                    )}
                  </>
                )}
                
                {(scan.results.type === "vulnerability_scan" || scan.results.alerts) && (
                  <>
                    <div>
                      <p className="text-sm text-muted-foreground">Total Vulnerabilities</p>
                      <p className="font-medium text-foreground">
                        {scan.results.summary?.total_alerts || 
                         scan.results.alerts?.alerts?.length || 
                         scan.results.total_vulnerabilities || 
                         scan.results.data?.length || 0}
                      </p>
                    </div>
                    <div>
                      <p className="text-sm text-muted-foreground">Critical</p>
                      <p className="font-medium text-foreground text-red-400">
                        {(scan.results.alerts?.alerts?.filter((a: any) => 
                          a.risk?.toLowerCase() === "critical"
                        )?.length || 0)}
                      </p>
                    </div>
                    <div>
                      <p className="text-sm text-muted-foreground">High</p>
                      <p className="font-medium text-foreground text-orange-400">
                        {(scan.results.alerts?.alerts?.filter((a: any) => 
                          a.risk?.toLowerCase() === "high"
                        )?.length || 0)}
                      </p>
                    </div>
                    <div>
                      <p className="text-sm text-muted-foreground">Medium</p>
                      <p className="font-medium text-foreground text-yellow-400">
                        {(scan.results.alerts?.alerts?.filter((a: any) => 
                          a.risk?.toLowerCase() === "medium"
                        )?.length || 0)}
                      </p>
                    </div>
                    <div>
                      <p className="text-sm text-muted-foreground">Low</p>
                      <p className="font-medium text-foreground text-blue-400">
                        {(scan.results.alerts?.alerts?.filter((a: any) => 
                          a.risk?.toLowerCase() === "low"
                        )?.length || 0)}
                      </p>
                    </div>
                    <div>
                      <p className="text-sm text-muted-foreground">Informational</p>
                      <p className="font-medium text-foreground text-gray-400">
                        {(scan.results.alerts?.alerts?.filter((a: any) => 
                          a.risk?.toLowerCase() === "informational" || 
                          a.risk?.toLowerCase() === "info" || 
                          !a.risk || 
                          a.risk === ""
                        )?.length || 0)}
                      </p>
                    </div>
                  </>
                )}

                {scan.results.type === "comprehensive_scan" && (
                  <>
                    <div>
                      <p className="text-sm text-muted-foreground">Total Ports</p>
                      <p className="font-medium text-foreground">{scan.results.port_scan?.total_ports || 0}</p>
                    </div>
                    <div>
                      <p className="text-sm text-muted-foreground">Open Ports</p>
                      <p className="font-medium text-foreground text-green-400">
                        {scan.results.port_scan?.open_ports || 0}
                      </p>
                    </div>
                    <div>
                      <p className="text-sm text-muted-foreground">Total Vulnerabilities</p>
                      <p className="font-medium text-foreground">{scan.results.vulnerability_scan?.total_vulnerabilities || 0}</p>
                    </div>
                    <div>
                      <p className="text-sm text-muted-foreground">Critical Vulns</p>
                      <p className="font-medium text-foreground text-red-400">
                        {scan.results.vulnerability_scan?.critical_vulnerabilities || 0}
                      </p>
                    </div>
                  </>
                )}
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* OS Detection Results */}
      {(scan.results.type === "port_scan" || scan.results.type === "comprehensive_scan") && 
       (scan.results.os_info || scan.results.port_scan?.os_info) && 
       Object.keys(scan.results.os_info || scan.results.port_scan?.os_info || {}).length > 0 && (
        <Card className="bg-blue-900/20 border-blue-700/50">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Monitor className="h-5 w-5 text-blue-400" />
              Operating System Detection
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div>
                  <p className="text-sm text-muted-foreground">OS Name</p>
                  <p className="font-medium text-foreground">{(scan.results.os_info || scan.results.port_scan?.os_info)?.name || 'Unknown'}</p>
                </div>
                <div>
                  <p className="text-sm text-muted-foreground">Accuracy</p>
                  <p className="font-medium text-foreground">{(scan.results.os_info || scan.results.port_scan?.os_info)?.accuracy || '0'}%</p>
                </div>
                <div>
                  <p className="text-sm text-muted-foreground">Detection Line</p>
                  <p className="font-medium text-foreground text-xs">{(scan.results.os_info || scan.results.port_scan?.os_info)?.line || 'No details available'}</p>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      )}



      {/* Detailed Results */}
      {(scan.results.type === "port_scan" || scan.results.open_ports || scan.results.data) && (
        <PortScanResults results={scan.results} expandedSections={expandedSections} toggleSection={toggleSection} />
      )}

      {scan.results.type === "vulnerability_scan" && (
        <VulnerabilityScanResults results={scan.results} expandedSections={expandedSections} toggleSection={toggleSection} />
      )}

      {scan.results.type === "comprehensive_scan" && (
        <div className="space-y-6">
          {/* Port Scan Results */}
          <div>
            <h3 className="text-lg font-semibold text-foreground mb-4 flex items-center gap-2">
              <Network className="h-5 w-5 text-blue-400" />
              Port Scan Results
            </h3>
            <PortScanResults results={scan.results.port_scan} expandedSections={expandedSections} toggleSection={toggleSection} />
          </div>
          
          {/* Vulnerability Scan Results */}
          <div>
            <h3 className="text-lg font-semibold text-foreground mb-4 flex items-center gap-2">
              <Shield className="h-5 w-5 text-red-400" />
              Vulnerability Scan Results
            </h3>
            <VulnerabilityScanResults results={scan.results.vulnerability_scan} expandedSections={expandedSections} toggleSection={toggleSection} />
          </div>
        </div>
      )}

      {/* Fallback for unknown result types */}
      {scan.results.type && !["port_scan", "vulnerability_scan", "comprehensive_scan"].includes(scan.results.type) && (
        <Card className="bg-secondary/30 border-border">
          <CardHeader>
            <CardTitle className="text-foreground">Raw Scan Results</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              <p className="text-sm text-muted-foreground">Scan Type: {scan.results.type}</p>
              <pre className="text-xs text-muted-foreground overflow-auto bg-secondary/50 p-2 rounded">
                {JSON.stringify(scan.results, null, 2)}
              </pre>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  )
}

function PortScanResults({ results, expandedSections, toggleSection }: any) {
  
  // Handle different result formats
  let portsData = []
  let openPorts = []
  let closedPorts = []
  let filteredPorts = []
  
  // Check if this is basic scanner format (has open_ports, closed_ports arrays)
  if (results.open_ports && Array.isArray(results.open_ports)) {
    openPorts = results.open_ports
    closedPorts = results.closed_ports || []
    filteredPorts = results.filtered_ports || []
    portsData = [...openPorts, ...closedPorts, ...filteredPorts]
  } else {
    // Standard format (has data array with state property)
    portsData = results.data || results || []
    openPorts = portsData.filter((port: any) => port.state === "open")
    closedPorts = portsData.filter((port: any) => port.state === "closed")
    filteredPorts = portsData.filter((port: any) => port.state === "filtered")
  }
  


  return (
    <div className="space-y-4">
      {/* Open Ports */}
      <Card className="bg-secondary/30 border-border">
        <CardHeader>
          <CardTitle className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Unlock className="h-5 w-5 text-green-400" />
              Open Ports ({openPorts.length})
            </div>
            <div className="flex items-center gap-2">
              <Button
                variant="ghost"
                size="sm"
                onClick={() => toggleSection("open")}
              >
                {expandedSections.includes("open") ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
              </Button>
            </div>
          </CardTitle>
        </CardHeader>
        <Collapsible open={expandedSections.includes("open")}>
          <CollapsibleContent>
            <CardContent>
              <div className="space-y-2">
                {openPorts.map((port: any, index: number) => (
                  <div key={index} className="flex items-center justify-between p-3 bg-green-900/20 border border-green-700/50 rounded-lg">
                    <div className="flex items-center gap-4">
                      <div className="text-center">
                        <p className="font-bold text-foreground">{port.port}</p>
                        <p className="text-xs text-muted-foreground">Port</p>
                      </div>
                      <div>
                        <p className="font-medium text-foreground capitalize">{port.service}</p>
                        <p className="text-sm text-muted-foreground">{port.version || "Version unknown"}</p>
                      </div>
                    </div>
                    <Badge className="bg-green-600">OPEN</Badge>
                  </div>
                ))}
              </div>
            </CardContent>
          </CollapsibleContent>
        </Collapsible>
      </Card>

      {/* Closed Ports */}
      <Card className="bg-secondary/30 border-border">
        <CardHeader>
          <CardTitle className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Lock className="h-5 w-5 text-red-400" />
              Closed Ports ({closedPorts.length})
            </div>
            <div className="flex items-center gap-2">
              <Button
                variant="ghost"
                size="sm"
                onClick={() => toggleSection("closed")}
              >
                {expandedSections.includes("closed") ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
              </Button>
            </div>
          </CardTitle>
        </CardHeader>
        <Collapsible open={expandedSections.includes("closed")}>
          <CollapsibleContent>
            <CardContent>
              <div className="space-y-2">
                {closedPorts.map((port: any, index: number) => (
                  <div key={index} className="flex items-center justify-between p-3 bg-red-900/20 border border-red-700/50 rounded-lg">
                    <div className="flex items-center gap-4">
                      <div className="text-center">
                        <p className="font-bold text-foreground">{port.port}</p>
                        <p className="text-xs text-muted-foreground">Port</p>
                      </div>
                      <div>
                        <p className="font-medium text-foreground capitalize">{port.service || "Unknown Service"}</p>
                        <p className="text-sm text-muted-foreground">{port.version || "No version detected"}</p>
                      </div>
                    </div>
                    <Badge className="bg-red-600">CLOSED</Badge>
                  </div>
                ))}
              </div>
            </CardContent>
          </CollapsibleContent>
        </Collapsible>
      </Card>

      {/* Filtered Ports */}
      <Card className="bg-secondary/30 border-border">
          <CardHeader>
            <CardTitle className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Shield className="h-5 w-5 text-yellow-400" />
                Filtered Ports ({filteredPorts.length})
              </div>
              <div className="flex items-center gap-2">
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => toggleSection("filtered")}
                >
                  {expandedSections.includes("filtered") ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
                </Button>
              </div>
            </CardTitle>
          </CardHeader>
          <Collapsible open={expandedSections.includes("filtered")}>
            <CollapsibleContent>
              <CardContent>
                <div className="space-y-2">
                  {filteredPorts.length > 0 ? (
                    filteredPorts.map((port: any, index: number) => (
                      <div key={index} className="flex items-center justify-between p-3 bg-yellow-900/20 border border-yellow-700/50 rounded-lg">
                        <div className="flex items-center gap-4">
                          <div className="text-center">
                            <p className="font-bold text-foreground">{port.port}</p>
                            <p className="text-xs text-muted-foreground">Port</p>
                          </div>
                          <div>
                            <p className="font-medium text-foreground capitalize">{port.service || "Unknown Service"}</p>
                            <p className="text-sm text-muted-foreground">{port.version || "No version detected"}</p>
                          </div>
                        </div>
                        <Badge className="bg-yellow-600">FILTERED</Badge>
                      </div>
                    ))
                  ) : (
                    <div className="p-4 text-center text-muted-foreground">
                      <Shield className="h-8 w-8 mx-auto mb-2 text-yellow-400" />
                      <p>No filtered ports found</p>
                      <p className="text-sm">Filtered ports are those that are blocked by firewalls</p>
                    </div>
                  )}
                </div>
              </CardContent>
            </CollapsibleContent>
          </Collapsible>
        </Card>
    </div>
  )
}

function VulnerabilityScanResults({ results, expandedSections, toggleSection }: any) {
  const [riskFilter, setRiskFilter] = useState<string>("All");

  // ZAP results structure fallback
  const alerts = results?.alerts?.alerts || [];

  // Map ZAP risk levels to consistent keys
  const riskMap: Record<string, string> = {
    "critical": "Critical",
    "high": "High", 
    "medium": "Medium",
    "low": "Low",
    "informational": "Informational",
    "info": "Informational",
    "": "Informational"
  };

  // Normalize risk for each alert
  const normalizedAlerts = alerts.map((alert: any) => ({
    ...alert,
    normalizedRisk: riskMap[(alert.risk || "informational").toLowerCase()] || "Informational"
  }));

  // Filtered alerts by risk
  const filteredAlerts = riskFilter === "All"
    ? normalizedAlerts
    : normalizedAlerts.filter((alert: any) => alert.normalizedRisk === riskFilter);

  // Count by risk
  const riskLevels = ["Critical", "High", "Medium", "Low", "Informational"];
  const riskCounts = riskLevels.reduce((acc, level) => {
    acc[level] = normalizedAlerts.filter((a: any) => a.normalizedRisk === level).length;
    return acc;
  }, {} as Record<string, number>);

  return (
    <div className="space-y-4">
      {/* Risk Level Dropdown */}
      <div className="flex items-center gap-4 mb-2">
        <Label htmlFor="risk-filter">Risk Level:</Label>
        <Select value={riskFilter} onValueChange={setRiskFilter}>
          <SelectTrigger className="w-48" id="risk-filter">
            <SelectValue>{riskFilter}</SelectValue>
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="All">All ({normalizedAlerts.length})</SelectItem>
            {riskLevels.map(level => (
              <SelectItem key={level} value={level}>{level} ({riskCounts[level]})</SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      {/* Vulnerabilities List/Table */}
      {filteredAlerts.length === 0 ? (
        <div className="text-muted-foreground">No vulnerabilities found for this risk level.</div>
      ) : (
        <div className="space-y-2">
          {filteredAlerts.map((alert: any, idx: number) => (
            <Card key={idx} className="border border-gray-700/50">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Badge>{alert.normalizedRisk}</Badge>
                  <span>{alert.name}</span>
                  <span className="text-xs text-muted-foreground">({alert.url})</span>
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-sm mb-1"><b>Description:</b> {alert.description}</div>
                {alert.solution && <div className="text-xs mb-1"><b>Solution:</b> {alert.solution}</div>}
                {alert.reference && <div className="text-xs"><b>Reference:</b> <a href={alert.reference.split("\n")[0]} target="_blank" rel="noopener noreferrer">{alert.reference.split("\n")[0]}</a></div>}
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}
