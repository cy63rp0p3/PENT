"use client"

import { useState } from "react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { useReportPromptContext } from "@/components/report-prompt-provider"
import { Zap, Network, Search } from "lucide-react"

export default function ScanIntegrationExample() {
  const [target, setTarget] = useState("")
  const [scanning, setScanning] = useState(false)
  const { showReportPrompt } = useReportPromptContext()

  // Example scan functions that would trigger the report prompt
  const simulateVulnerabilityScan = async () => {
    if (!target.trim()) return
    
    setScanning(true)
    
    // Simulate scan delay
    await new Promise(resolve => setTimeout(resolve, 3000))
    
    // Simulate scan results
    const mockResults = {
      critical_vulnerabilities: [
        {
          title: "SQL Injection Vulnerability",
          description: "Found SQL injection vulnerability in login form",
          cvss_score: 9.8,
          cve_id: "CVE-2023-1234"
        }
      ],
      high_vulnerabilities: [
        {
          title: "XSS Vulnerability",
          description: "Cross-site scripting vulnerability detected",
          cvss_score: 7.5,
          cve_id: "CVE-2023-5678"
        }
      ],
      medium_vulnerabilities: [],
      low_vulnerabilities: [
        {
          title: "Information Disclosure",
          description: "Server version information exposed",
          cvss_score: 3.1
        }
      ]
    }
    
    // Show report prompt with results
    showReportPrompt({
      scan_type: 'vulnerability_scan',
      target: target,
      results: mockResults,
      scan_id: `vuln_${Date.now()}`,
      timestamp: new Date().toISOString(),
      status: 'completed'
    })
    
    setScanning(false)
  }

  const simulatePortScan = async () => {
    if (!target.trim()) return
    
    setScanning(true)
    
    // Simulate scan delay
    await new Promise(resolve => setTimeout(resolve, 2000))
    
    // Simulate scan results
    const mockResults = {
      open_ports: [
        { port: 22, service: "SSH", version: "OpenSSH 8.2p1" },
        { port: 80, service: "HTTP", version: "Apache/2.4.41" },
        { port: 443, service: "HTTPS", version: "Apache/2.4.41" },
        { port: 3306, service: "MySQL", version: "MySQL 8.0.26" }
      ],
      closed_ports: [21, 23, 25, 53, 110, 143, 993, 995],
      filtered_ports: [135, 139, 445, 1433, 1521, 3389]
    }
    
    // Show report prompt with results
    showReportPrompt({
      scan_type: 'port_scan',
      target: target,
      results: mockResults,
      scan_id: `port_${Date.now()}`,
      timestamp: new Date().toISOString(),
      status: 'completed'
    })
    
    setScanning(false)
  }

  const simulateSubdomainScan = async () => {
    if (!target.trim()) return
    
    setScanning(true)
    
    // Simulate scan delay
    await new Promise(resolve => setTimeout(resolve, 1500))
    
    // Simulate scan results
    const mockResults = {
      subdomains: [
        "www.example.com",
        "mail.example.com",
        "admin.example.com",
        "api.example.com",
        "dev.example.com",
        "staging.example.com"
      ],
      ssl_info: {
        valid: true,
        issuer: "Let's Encrypt",
        expiry: "2024-12-31"
      },
      reputation: {
        suspicious: false,
        malware_detected: false
      }
    }
    
    // Show report prompt with results
    showReportPrompt({
      scan_type: 'subdomain',
      target: target,
      results: mockResults,
      scan_id: `sub_${Date.now()}`,
      timestamp: new Date().toISOString(),
      status: 'completed'
    })
    
    setScanning(false)
  }

  return (
    <Card className="w-full max-w-2xl mx-auto">
      <CardHeader>
        <CardTitle>Report Prompt Integration Example</CardTitle>
        <CardDescription>
          This demonstrates how the report prompt system works. After each scan completes, 
          users will be prompted to save the results as a report.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="space-y-2">
          <Label htmlFor="target">Target Domain</Label>
          <Input
            id="target"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="example.com"
            className="w-full"
          />
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          <Button
            onClick={simulateVulnerabilityScan}
            disabled={scanning || !target.trim()}
            className="w-full"
          >
            <Zap className="h-4 w-4 mr-2" />
            {scanning ? 'Scanning...' : 'Vulnerability Scan'}
          </Button>

          <Button
            onClick={simulatePortScan}
            disabled={scanning || !target.trim()}
            className="w-full"
          >
            <Network className="h-4 w-4 mr-2" />
            {scanning ? 'Scanning...' : 'Port Scan'}
          </Button>

          <Button
            onClick={simulateSubdomainScan}
            disabled={scanning || !target.trim()}
            className="w-full"
          >
            <Search className="h-4 w-4 mr-2" />
            {scanning ? 'Scanning...' : 'Subdomain Scan'}
          </Button>
        </div>

        <div className="text-sm text-muted-foreground">
          <p>How it works:</p>
          <ol className="list-decimal list-inside space-y-1 mt-2">
            <li>Enter a target domain and click any scan button</li>
            <li>The scan will simulate for a few seconds</li>
            <li>When complete, a report prompt will appear</li>
            <li>You can save the results as a report or skip</li>
            <li>Saved reports appear in the Reports page</li>
          </ol>
        </div>
      </CardContent>
    </Card>
  )
} 