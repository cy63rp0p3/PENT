"use client"

import { useState } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Badge } from "@/components/ui/badge"
import { Progress } from "@/components/ui/progress"
import { 
  Network, 
  Play, 
  Square, 
  Target, 
  Clock, 
  CheckCircle,
  XCircle,
  Loader2,
  Info,
  Server,
  Lock,
  Unlock
} from "lucide-react"

interface BasicPortScannerProps {
  onScanComplete: (results: any) => void
}

interface PortResult {
  port: number
  status: 'open' | 'closed' | 'filtered'
  service?: string
  response_time?: number
}

export default function BasicPortScanner({ onScanComplete }: BasicPortScannerProps) {
  const [target, setTarget] = useState("")
  const [portRange, setPortRange] = useState("1-1000")
  const [scanning, setScanning] = useState(false)
  const [progress, setProgress] = useState(0)
  const [results, setResults] = useState<PortResult[]>([])
  const [currentPort, setCurrentPort] = useState(0)

  const commonPorts = [
    { port: 20, service: "FTP-DATA" },
    { port: 21, service: "FTP" },
    { port: 22, service: "SSH" },
    { port: 23, service: "Telnet" },
    { port: 25, service: "SMTP" },
    { port: 53, service: "DNS" },
    { port: 67, service: "DHCP" },
    { port: 68, service: "DHCP" },
    { port: 69, service: "TFTP" },
    { port: 80, service: "HTTP" },
    { port: 110, service: "POP3" },
    { port: 123, service: "NTP" },
    { port: 135, service: "RPC" },
    { port: 137, service: "NetBIOS" },
    { port: 138, service: "NetBIOS" },
    { port: 139, service: "NetBIOS" },
    { port: 143, service: "IMAP" },
    { port: 161, service: "SNMP" },
    { port: 162, service: "SNMP-TRAP" },
    { port: 389, service: "LDAP" },
    { port: 443, service: "HTTPS" },
    { port: 445, service: "SMB" },
    { port: 465, service: "SMTPS" },
    { port: 514, service: "Syslog" },
    { port: 515, service: "LPR" },
    { port: 587, service: "SMTP" },
    { port: 636, service: "LDAPS" },
    { port: 993, service: "IMAPS" },
    { port: 995, service: "POP3S" },
    { port: 1433, service: "MSSQL" },
    { port: 1521, service: "Oracle" },
    { port: 1723, service: "PPTP" },
    { port: 3306, service: "MySQL" },
    { port: 3389, service: "RDP" },
    { port: 5432, service: "PostgreSQL" },
    { port: 5900, service: "VNC" },
    { port: 5984, service: "CouchDB" },
    { port: 6379, service: "Redis" },
    { port: 8080, service: "HTTP-Alt" },
    { port: 8443, service: "HTTPS-Alt" },
    { port: 9000, service: "Webmin" },
    { port: 9090, service: "HTTP-Alt" },
    { port: 9200, service: "Elasticsearch" },
    { port: 27017, service: "MongoDB" }
  ]

  const portRanges = [
    { value: "1-100", label: "Well-known ports (1-100)" },
    { value: "1-1000", label: "Common ports (1-1000)" },
    { value: "1-10000", label: "Extended range (1-10000)" },
    { value: "common", label: "Common services only" }
  ]

  const validateTarget = (target: string): boolean => {
    // Basic validation for IP or domain
    const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/
    const domainRegex = /^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$/
    
    return ipRegex.test(target) || domainRegex.test(target)
  }

  const parsePortRange = (range: string): number[] => {
    if (range === "common") {
      return commonPorts.map(p => p.port)
    }
    
    const [start, end] = range.split('-').map(Number)
    const ports: number[] = []
    
    for (let i = start; i <= end; i++) {
      ports.push(i)
    }
    
    return ports
  }

  const getServiceName = (port: number): string => {
    const commonPort = commonPorts.find(p => p.port === port)
    if (commonPort) {
      return commonPort.service
    }
    
    // Additional service identification based on port ranges
    if (port >= 1 && port <= 1023) {
      return "Well-known service"
    } else if (port >= 1024 && port <= 49151) {
      return "Registered service"
    } else if (port >= 49152 && port <= 65535) {
      return "Dynamic/Private service"
    }
    
    return "Unknown"
  }

  const performRealPortScan = async (target: string, portRange: string): Promise<any> => {
    try {
      const response = await fetch('http://localhost:8000/api/scan/basic-port-scan/', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          target: target,
          port_range: portRange
        })
      })
      
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`)
      }
      
      const data = await response.json()
      return data
    } catch (error) {
      console.error('Port scan error:', error)
      throw error
    }
  }

  const startScan = async () => {
    if (!target.trim()) {
      return
    }

    if (!validateTarget(target)) {
      return
    }
    setScanning(true)
    setProgress(0)
    setResults([])
    setCurrentPort(0)

    try {
      // Show progress updates during scan
      const progressInterval = setInterval(() => {
        setProgress(prev => Math.min(prev + 5, 90)) // Progress up to 90% during scan
      }, 500)

      // Perform real port scan
      const scanData = await performRealPortScan(target, portRange)
      
      clearInterval(progressInterval)
      setProgress(100)
      
      // Convert backend results to frontend format
      const allResults = [
        ...scanData.open_ports,
        ...scanData.closed_ports,
        ...scanData.filtered_ports
      ]
      
      setResults(allResults)
      
      // Format results for the main scanning system
      const formattedResults = {
        target: target,
        scan_type: "real_basic_port_scan",
        timestamp: new Date().toISOString(),
        ports_scanned: scanData.ports_scanned,
        open_ports: scanData.open_ports,
        closed_ports: scanData.closed_ports,
        filtered_ports: scanData.filtered_ports,
        summary: scanData.summary
      }
      
      onScanComplete(formattedResults)
      
    } catch (error) {
      console.error('Scan error:', error)
      // Show error to user
      alert(`Scan failed: ${error.message}`)
    } finally {
      setScanning(false)
      setProgress(100)
    }
  }

  const stopScan = () => {
    setScanning(false)
    setProgress(0)
    setCurrentPort(0)
  }

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'open':
        return <Unlock className="h-4 w-4 text-green-500" />
      case 'closed':
        return <Lock className="h-4 w-4 text-red-500" />
      case 'filtered':
        return <XCircle className="h-4 w-4 text-yellow-500" />
      default:
        return <Info className="h-4 w-4 text-gray-500" />
    }
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'open':
        return "bg-green-100 text-green-800 dark:bg-green-900/20 dark:text-green-300"
      case 'closed':
        return "bg-red-100 text-red-800 dark:bg-red-900/20 dark:text-red-300"
      case 'filtered':
        return "bg-yellow-100 text-yellow-800 dark:bg-yellow-900/20 dark:text-yellow-300"
      default:
        return "bg-gray-100 text-gray-800 dark:bg-gray-900/20 dark:text-gray-300"
    }
  }

  const openPorts = results.filter(r => r.status === 'open')
  const closedPorts = results.filter(r => r.status === 'closed')
  const filteredPorts = results.filter(r => r.status === 'filtered')

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <Network className="h-5 w-5" />
            <CardTitle>Basic Port Scanner</CardTitle>
          </div>
          <CardDescription>
            Real port scanning using Python socket connections. Scans ports for actual open services.
          </CardDescription>
          <div className="bg-green-900/20 border border-green-700/50 rounded-lg p-3">
            <div className="flex items-start gap-2">
              <Info className="h-4 w-4 text-green-400 mt-0.5 flex-shrink-0" />
              <div className="text-sm">
                <p className="font-medium text-green-300 mb-1">Real Port Scanner Features:</p>
                <ul className="text-green-200 space-y-1 text-xs">
                  <li>• Performs actual network port scanning</li>
                  <li>• Uses concurrent connections for faster scanning</li>
                  <li>• Service identification based on common port mappings</li>
                  <li>• 2-second timeout per port for reliable results</li>
                </ul>
              </div>
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label htmlFor="target">Target Host/IP</Label>
              <Input
                id="target"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder="example.com or 192.168.1.1"
                disabled={scanning}
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="port-range">Port Range</Label>
              <Select value={portRange} onValueChange={setPortRange} disabled={scanning}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {portRanges.map((range) => (
                    <SelectItem key={range.value} value={range.value}>
                      {range.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>

          {scanning && (
            <div className="space-y-2">
              <div className="flex items-center justify-between text-sm">
                <span>Scanning port {currentPort}...</span>
                <span>{Math.round(progress)}%</span>
              </div>
              <Progress value={progress} className="w-full" />
            </div>
          )}

          <div className="flex gap-2">
            <Button
              onClick={startScan}
              disabled={scanning || !target.trim()}
              className="flex-1"
            >
              {scanning ? (
                <>
                  <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                  Scanning...
                </>
              ) : (
                <>
                  <Play className="h-4 w-4 mr-2" />
                  Start Scan
                </>
              )}
            </Button>
            
            {scanning && (
              <Button
                onClick={stopScan}
                variant="outline"
                className="flex-1"
              >
                <Square className="h-4 w-4 mr-2" />
                Stop Scan
              </Button>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Results */}
      {results.length > 0 && (
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Server className="h-5 w-5" />
                <CardTitle>Scan Results</CardTitle>
              </div>
              <div className="flex gap-2">
                <Badge variant="outline" className="text-green-600">
                  {openPorts.length} Open
                </Badge>
                <Badge variant="outline" className="text-red-600">
                  {closedPorts.length} Closed
                </Badge>
                <Badge variant="outline" className="text-yellow-600">
                  {filteredPorts.length} Filtered
                </Badge>
              </div>
            </div>
            <CardDescription>
              Port scan completed for {target} - {results.length} ports scanned
            </CardDescription>
          </CardHeader>
          <CardContent>
            {openPorts.length > 0 && (
              <div className="space-y-4">
                <h3 className="text-lg font-semibold text-green-600 dark:text-green-400">
                  Open Ports ({openPorts.length})
                </h3>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                  {openPorts.map((port) => (
                    <div
                      key={port.port}
                      className="p-3 border border-green-200 dark:border-green-800 rounded-lg bg-green-50 dark:bg-green-900/20"
                    >
                      <div className="flex items-center justify-between mb-2">
                        <div className="flex items-center gap-2">
                          {getStatusIcon(port.status)}
                          <span className="font-mono font-semibold">Port {port.port}</span>
                        </div>
                        <Badge className={getStatusColor(port.status)}>
                          {port.status}
                        </Badge>
                      </div>
                      <div className="text-sm text-muted-foreground">
                        <div>Service: {port.service}</div>
                        <div>Response: {port.response_time}ms</div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {openPorts.length === 0 && (
              <div className="text-center py-8">
                <Lock className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
                <p className="text-muted-foreground">No open ports found</p>
                <p className="text-sm text-muted-foreground">
                  All scanned ports are either closed or filtered
                </p>
              </div>
            )}

            <div className="mt-6 p-4 bg-gray-50 dark:bg-gray-900/50 rounded-lg">
              <h4 className="font-semibold mb-2">Scan Summary</h4>
              <div className="grid grid-cols-3 gap-4 text-sm">
                <div>
                  <div className="text-muted-foreground">Total Ports</div>
                  <div className="font-semibold">{results.length}</div>
                </div>
                <div>
                  <div className="text-muted-foreground">Open</div>
                  <div className="font-semibold text-green-600">{openPorts.length}</div>
                </div>
                <div>
                  <div className="text-muted-foreground">Closed/Filtered</div>
                  <div className="font-semibold text-red-600">{closedPorts.length + filteredPorts.length}</div>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  )
} 