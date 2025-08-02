"use client"

import { useState, Suspense, useEffect } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Badge } from "@/components/ui/badge"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { 
  Search, 
  Globe, 
  NetworkIcon as Dns, 
  MapPin, 
  Loader2, 
  Eye, 
  Target, 
  Shield, 
  Activity,
  Zap,
  Database,
  Network,
  Server,
  Fingerprint,
  Users,
  Building,
  Mail,
  FileText
} from "lucide-react"
import { useScrollbarAutoHide } from "@/hooks/useScrollbarAutoHide"
import { Progress } from "@/components/ui/progress"
import { useBackgroundScans } from "@/hooks/useBackgroundScans"
import { useReportPromptContext } from "@/components/report-prompt-provider"

// Lazy load the heavy scrollbar hook
const LazyScrollbarHook = ({ children, timeout }: { children: any, timeout: number }) => {
  const scrollbar = useScrollbarAutoHide(timeout)
  return children(scrollbar)
}

export default function ReconnaissancePage() {
  const [target, setTarget] = useState("")
  const [activeTab, setActiveTab] = useState("whoislookup")
  const [whoisView, setWhoisView] = useState<string | null>(null)
  const [subdomainView, setSubdomainView] = useState<string | null>(null)
  const subdomainScrollbar = useScrollbarAutoHide(2000)
  const dnsScrollbar = useScrollbarAutoHide(2000)
  
  const { startScan, activeScans, cancelScan } = useBackgroundScans()
  const { showReportPrompt } = useReportPromptContext()

  const stripProtocol = (input: string) => input.replace(/^https?:\/\//, "").replace(/\/$/, "")

  // Get the most recent scan for display
  const mostRecentScan = activeScans.length > 0 ? activeScans[activeScans.length - 1] : null
  const isScanning = activeScans.some(scan => scan.status === 'running')

  // Check for completed scans and show report prompt
  useEffect(() => {
    activeScans.forEach(scan => {
      if (scan.status === 'completed' && scan.results && !scan.reportPromptShown) {
        // Mark this scan as having shown the prompt
        scan.reportPromptShown = true
        
        // Show the report prompt
        showReportPrompt({
          scan_type: scan.scanType,
          target: scan.target,
          results: scan.results,
          scan_id: scan.scanId,
          timestamp: new Date().toISOString(),
          status: 'completed'
        })
      }
    })
  }, [activeScans, showReportPrompt])

  // Subdomain tool actions
  const handleSubdomainEnum = async (view: string) => {
    setSubdomainView(view)
    try {
      const response = await fetch('http://localhost:8000/api/recon/subdomain/', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ 
          target: stripProtocol(target),
          tool_type: view
        }),
      })
      const data = await response.json()
      if (data.scan_id) {
        startScan({
          scanId: data.scan_id,
          target: stripProtocol(target),
          scanType: 'subdomain',
          toolType: view
        })
      }
    } catch (error) {
      console.error('Failed to start subdomain scan:', error)
    }
  }

  // WHOIS tool actions
  const handleWhoisLookup = async (view: string) => {
    setWhoisView(view)
    try {
      const response = await fetch('http://localhost:8000/api/recon/whois/', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ target: stripProtocol(target) }),
      })
      const data = await response.json()
      if (data.scan_id) {
        startScan({
          scanId: data.scan_id,
          target: stripProtocol(target),
          scanType: 'whois',
          toolType: view
        })
      }
    } catch (error) {
      console.error('Failed to start WHOIS lookup:', error)
    }
  }

  // DNS tool actions
  const handleDnsLookup = async () => {
    try {
      const response = await fetch('http://localhost:8000/api/recon/dns/', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ target: stripProtocol(target) }),
      })
      const data = await response.json()
      if (data.scan_id) {
        startScan({
          scanId: data.scan_id,
          target: stripProtocol(target),
          scanType: 'dns',
          toolType: 'dns_lookup'
        })
      }
    } catch (error) {
      console.error('Failed to start DNS lookup:', error)
    }
  }

  // Get current scan results for display
  const getCurrentResults = () => {
    if (!mostRecentScan || mostRecentScan.status !== 'completed') return null
    return mostRecentScan.results
  }

  const results = getCurrentResults()
  const currentProgress = mostRecentScan?.progress || 0



  const reconnaissanceTools = [
    {
      name: "WHOIS Lookup",
      tools: [
        { name: "Domain Information", icon: Globe, color: "bg-blue-600", action: () => handleWhoisLookup('domain') },
        { name: "Registrar Details", icon: Building, color: "bg-indigo-600", action: () => handleWhoisLookup('registrar') },
        { name: "Registration History", icon: Activity, color: "bg-purple-600", action: () => handleWhoisLookup('history') },
        { name: "Nameserver Analysis", icon: Server, color: "bg-cyan-600", action: () => handleWhoisLookup('nameservers') },
      ]
    },
    {
      name: "Subdomain Enumeration", 
      tools: [
        { name: "DNS Bruteforce", icon: Search, color: "bg-green-600", action: () => handleSubdomainEnum('bruteforce') },
        { name: "Certificate Transparency", icon: Shield, color: "bg-orange-600", action: () => handleSubdomainEnum('certificate') },
        { name: "Search Engine Discovery", icon: Eye, color: "bg-teal-600", action: () => handleSubdomainEnum('search') },
        { name: "VirusTotal Lookup", icon: Target, color: "bg-red-600", action: () => handleSubdomainEnum('virustotal') },
      ]
    },
    {
      name: "DNS Lookup",
      tools: [
        { name: "A Records", icon: Dns, color: "bg-emerald-600", action: handleDnsLookup },
        { name: "MX Records", icon: Mail, color: "bg-pink-600", action: handleDnsLookup },
        { name: "TXT Records", icon: FileText, color: "bg-yellow-600", action: handleDnsLookup },
        { name: "All DNS Records", icon: Database, color: "bg-rose-600", action: handleDnsLookup },
      ]
    }
  ]

  return (
    <div className="space-y-6">
      {/* Header Section */}
      <div className="bg-gradient-to-r from-card to-card rounded-xl p-6 border border-border">
        <div className="flex items-center space-x-4 mb-4">
          <div className="p-3 bg-blue-600 rounded-xl">
            <Eye className="h-8 w-8 text-white" />
          </div>
          <div>
            <h1 className="text-3xl font-bold text-foreground">Reconnaissance Center</h1>
            <p className="text-muted-foreground">Intelligence gathering and target analysis platform</p>
          </div>
        </div>
        
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="bg-secondary rounded-xl p-4">
            <div className="flex items-center space-x-2 mb-2">
              <Target className="h-5 w-5 text-blue-400" />
              <span className="text-foreground font-medium">Target</span>
            </div>
            <Input
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="Enter domain or IP address"
              className="rounded-xl"
            />
          </div>
          
          <div className="bg-secondary rounded-xl p-4">
            <div className="flex items-center space-x-2 mb-2">
              <Activity className="h-5 w-5 text-green-400" />
              <span className="text-foreground font-medium">Status</span>
            </div>
            <Badge variant="outline" className="border-green-500 text-green-400 rounded-lg">
              {isScanning ? "Scanning..." : "Ready"}
            </Badge>
            {isScanning && (
              <div className="mt-3">
                <Progress value={currentProgress} className="h-2" />
                <p className="text-xs text-muted-foreground mt-1">{Math.round(currentProgress)}%</p>
              </div>
            )}
          </div>
          
          <div className="bg-secondary rounded-xl p-4">
            <div className="flex items-center space-x-2 mb-2">
              <Zap className="h-5 w-5 text-yellow-400" />
              <span className="text-foreground font-medium">Last Scan</span>
            </div>
            <span className="text-muted-foreground text-sm">
              {mostRecentScan ? (
                <div>
                  <div className="capitalize">{mostRecentScan.scanType} {mostRecentScan.toolType && `(${mostRecentScan.toolType})`}</div>
                  <div className="text-xs">{mostRecentScan.target}</div>
                  <div className="text-xs">
                    {mostRecentScan.status === 'running' ? 'In progress...' : 
                     mostRecentScan.status === 'completed' ? 'Completed' :
                     mostRecentScan.status === 'cancelled' ? 'Cancelled' : 'Error'}
                  </div>
                </div>
              ) : (
                "No scans yet"
              )}
            </span>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        {/* Tools Panel */}
        <div className="xl:col-span-1">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center">
                <Target className="h-5 w-5 mr-2 text-blue-400" />
                Reconnaissance Tools
              </CardTitle>
              <CardDescription>
                Select reconnaissance techniques to gather intelligence
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
                <TabsList className="grid w-full grid-cols-3 rounded-xl">
                  <TabsTrigger value="whoislookup" className="text-xs rounded-lg">WHOIS</TabsTrigger>
                  <TabsTrigger value="subdomainenumeration" className="text-xs rounded-lg">Subdomains</TabsTrigger>
                  <TabsTrigger value="dnslookup" className="text-xs rounded-lg">DNS</TabsTrigger>
                </TabsList>
                
                {reconnaissanceTools.map((category) => (
                  <TabsContent key={category.name} value={category.name.toLowerCase().replace(/\s+/g, '')} className="space-y-3 mt-4">
                    {category.tools.map((tool) => (
                      <Button
                        key={tool.name}
                        onClick={tool.action}
                        disabled={!target || isScanning}
                        className={`w-full justify-start ${tool.color} hover:opacity-90 text-white rounded-xl`}
                        variant="ghost"
                      >
                        <tool.icon className="h-4 w-4 mr-3" />
                        <span className="text-sm">{tool.name}</span>
                        {isScanning && <Loader2 className="h-4 w-4 animate-spin ml-auto" />}
                      </Button>
                    ))}
                  </TabsContent>
                ))}
              </Tabs>
            </CardContent>
          </Card>
        </div>

        {/* Results Panel */}
        <div className="xl:col-span-2">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center">
                <Search className="h-5 w-5 mr-2 text-green-400" />
                Intelligence Results
              </CardTitle>
              <CardDescription>
                {results ? `Analysis results for: ${mostRecentScan?.target || target}` : "No reconnaissance data available"}
              </CardDescription>
            </CardHeader>
            <CardContent>


              {isScanning && mostRecentScan && (
                <div className="flex justify-end mb-4">
                  <Button variant="destructive" onClick={() => cancelScan(mostRecentScan.scanId)} className="rounded-lg">
                    Cancel Scan
                  </Button>
                </div>
              )}
              {!results ? (
                <div className="text-center py-12">
                  <div className="bg-secondary rounded-full w-20 h-20 flex items-center justify-center mx-auto mb-4">
                    <MapPin className="h-10 w-10 text-muted-foreground" />
                  </div>
                  <h3 className="text-foreground font-medium mb-2">No Intelligence Gathered</h3>
                  <p className="text-muted-foreground text-sm mb-4">
                    Enter a target and select reconnaissance tools to begin intelligence gathering.
                  </p>
                  <div className="flex justify-center space-x-2">
                    <Badge variant="outline" className="border-blue-500 text-blue-400">WHOIS</Badge>
                    <Badge variant="outline" className="border-green-500 text-green-400">DNS</Badge>
                    <Badge variant="outline" className="border-purple-500 text-purple-400">Subdomains</Badge>
                  </div>
                </div>
              ) : (
                <div className="space-y-6">
                  {results?.type === "subdomains" && (
                    <div>
                      <div className="flex items-center justify-between mb-4">
                        <h3 className="text-foreground font-medium text-lg flex items-center">
                          <Search className="h-5 w-5 mr-2 text-purple-400" />
                          {subdomainView === 'bruteforce' && 'DNS Bruteforce Results'}
                          {subdomainView === 'certificate' && 'Certificate Transparency Results'}
                          {subdomainView === 'search' && 'Search Engine Discovery Results'}
                          {subdomainView === 'virustotal' && 'VirusTotal Lookup Results'}
                          {!subdomainView && 'Discovered Subdomains'}
                        </h3>
                        <div className="flex items-center space-x-2">
                          <Badge className="bg-purple-600 text-white">
                            {results.data.subdomains?.length || 0} found
                          </Badge>
                          {results.data.total_checked && (
                            <Badge variant="outline" className="text-muted-foreground">
                              {results.data.total_checked} checked
                            </Badge>
                          )}
                        </div>
                      </div>
                      {results.error && (
                        <div className="mb-4 p-3 bg-red-100 dark:bg-red-900/20 border border-red-300 dark:border-red-700 rounded-lg">
                          <p className="text-red-700 dark:text-red-300 text-sm">{results.error}</p>
                        </div>
                      )}
                      
                      {/* DNS Bruteforce View */}
                      {subdomainView === 'bruteforce' && (
                        <div
                          className={`grid grid-cols-1 md:grid-cols-2 gap-3 max-h-96 overflow-y-auto ${subdomainScrollbar.showScrollbar ? 'scrollbar-show' : 'scrollbar-hide'}`}
                          onMouseEnter={subdomainScrollbar.handleMouseEnter}
                          onMouseLeave={subdomainScrollbar.handleMouseLeave}
                        >
                          {results.data.subdomains && results.data.subdomains.length > 0 ? (
                            results.data.subdomains.map((item: any, index: number) => (
                              <div
                                key={index}
                                className="p-4 bg-secondary rounded-xl border border-border hover:border-border transition-colors"
                              >
                                <div className="flex items-center justify-between mb-2">
                                  <p className="text-foreground font-medium text-sm break-all">{item.subdomain}</p>
                                  <Badge
                                    variant={item.status === "active" ? "default" : "secondary"}
                                    className="text-xs"
                                  >
                                    {item.status}
                                  </Badge>
                                </div>
                                <p className="text-muted-foreground text-xs">{item.ip}</p>
                                <div className="mt-2 space-y-1">
                                  <Badge variant="outline" className="text-xs">
                                    Response: {item.response_time || 0}ms
                                  </Badge>
                                  {item.dns_records && item.dns_records.length > 0 && (
                                    <div className="flex flex-wrap gap-1 mt-1">
                                      {item.dns_records.slice(0, 3).map((record: any, idx: number) => (
                                        <Badge key={idx} variant="outline" className="text-xs">
                                          {record.type}: {record.value.substring(0, 20)}...
                                        </Badge>
                                      ))}
                                    </div>
                                  )}
                                </div>
                              </div>
                            ))
                          ) : (
                            <div className="col-span-2 text-center py-8">
                              <p className="text-muted-foreground">No subdomains found via DNS bruteforce</p>
                            </div>
                          )}
                        </div>
                      )}

                      {/* Certificate Transparency View */}
                      {subdomainView === 'certificate' && (
                        <div
                          className={`grid grid-cols-1 md:grid-cols-2 gap-3 max-h-96 overflow-y-auto ${subdomainScrollbar.showScrollbar ? 'scrollbar-show' : 'scrollbar-hide'}`}
                          onMouseEnter={subdomainScrollbar.handleMouseEnter}
                          onMouseLeave={subdomainScrollbar.handleMouseLeave}
                        >
                          {results.data.subdomains && results.data.subdomains.length > 0 ? (
                            results.data.subdomains.map((item: any, index: number) => (
                              <div
                                key={index}
                                className="p-4 bg-secondary rounded-xl border border-border hover:border-border transition-colors"
                              >
                                <div className="flex items-center justify-between mb-2">
                                  <p className="text-foreground font-medium text-sm break-all">{item.subdomain}</p>
                                  <Badge className={item.ssl_certificate?.valid ? "bg-orange-600 text-white text-xs" : "bg-gray-600 text-white text-xs"}>
                                    {item.ssl_certificate?.valid ? "SSL Valid" : "No SSL"}
                                  </Badge>
                                </div>
                                <p className="text-muted-foreground text-xs">{item.ip}</p>
                                <div className="mt-2 space-y-1">
                                  <p className="text-muted-foreground text-xs">Issuer: {item.ssl_issuer || 'Unknown'}</p>
                                  {item.ssl_expiry && (
                                    <p className="text-muted-foreground text-xs">Expires: {new Date(item.ssl_expiry).toLocaleDateString()}</p>
                                  )}
                                  {item.ssl_subject_alt_names && item.ssl_subject_alt_names.length > 0 && (
                                    <div className="flex flex-wrap gap-1 mt-1">
                                      <Badge variant="outline" className="text-xs">
                                        SAN: {item.ssl_subject_alt_names.length} domains
                                      </Badge>
                                    </div>
                                  )}
                                </div>
                              </div>
                            ))
                          ) : (
                            <div className="col-span-2 text-center py-8">
                              <p className="text-muted-foreground">No SSL certificates found</p>
                            </div>
                          )}
                        </div>
                      )}

                      {/* Search Engine Discovery View */}
                      {subdomainView === 'search' && (
                        <div
                          className={`grid grid-cols-1 md:grid-cols-2 gap-3 max-h-96 overflow-y-auto ${subdomainScrollbar.showScrollbar ? 'scrollbar-show' : 'scrollbar-hide'}`}
                          onMouseEnter={subdomainScrollbar.handleMouseEnter}
                          onMouseLeave={subdomainScrollbar.handleMouseLeave}
                        >
                          {results.data.subdomains && results.data.subdomains.length > 0 ? (
                            results.data.subdomains.map((item: any, index: number) => (
                              <div
                                key={index}
                                className="p-4 bg-secondary rounded-xl border border-border hover:border-border transition-colors"
                              >
                                <div className="flex items-center justify-between mb-2">
                                  <p className="text-foreground font-medium text-sm break-all">{item.subdomain}</p>
                                  <Badge className={item.indexed ? "bg-teal-600 text-white text-xs" : "bg-gray-600 text-white text-xs"}>
                                    {item.indexed ? "Indexed" : "Not Indexed"}
                                  </Badge>
                                </div>
                                <p className="text-muted-foreground text-xs">{item.ip}</p>
                                <div className="mt-2 space-y-1">
                                  {item.search_engines && item.search_engines.length > 0 && (
                                    <div className="flex flex-wrap gap-1">
                                      {item.search_engines.map((engine: string, idx: number) => (
                                        <Badge key={idx} variant="outline" className="text-xs">
                                          {engine}
                                        </Badge>
                                      ))}
                                    </div>
                                  )}
                                  {item.page_rank && item.page_rank > 0 && (
                                    <Badge variant="outline" className="text-xs">
                                      Page Rank: {item.page_rank}/10
                                    </Badge>
                                  )}
                                  {item.last_seen && (
                                    <p className="text-muted-foreground text-xs">Last seen: {item.last_seen}</p>
                                  )}
                                </div>
                              </div>
                            ))
                          ) : (
                            <div className="col-span-2 text-center py-8">
                              <p className="text-muted-foreground">No subdomains found via search engines</p>
                            </div>
                          )}
                        </div>
                      )}

                      {/* VirusTotal Lookup View */}
                      {subdomainView === 'virustotal' && (
                        <div
                          className={`grid grid-cols-1 md:grid-cols-2 gap-3 max-h-96 overflow-y-auto ${subdomainScrollbar.showScrollbar ? 'scrollbar-show' : 'scrollbar-hide'}`}
                          onMouseEnter={subdomainScrollbar.handleMouseEnter}
                          onMouseLeave={subdomainScrollbar.handleMouseLeave}
                        >
                          {results.data.subdomains && results.data.subdomains.length > 0 ? (
                            results.data.subdomains.map((item: any, index: number) => (
                              <div
                                key={index}
                                className="p-4 bg-secondary rounded-xl border border-border hover:border-border transition-colors"
                              >
                                <div className="flex items-center justify-between mb-2">
                                  <p className="text-foreground font-medium text-sm break-all">{item.subdomain}</p>
                                  <Badge className={
                                    item.reputation === "Clean" ? "bg-green-600 text-white text-xs" :
                                    item.reputation === "Low Risk" ? "bg-yellow-600 text-white text-xs" :
                                    "bg-red-600 text-white text-xs"
                                  }>
                                    {item.reputation || "Unknown"}
                                  </Badge>
                                </div>
                                <p className="text-muted-foreground text-xs">{item.ip}</p>
                                <div className="mt-2 space-y-1">
                                  <Badge variant="outline" className="text-xs">
                                    {item.detections || 0}/{item.virustotal_data?.total_engines || 90} Detections
                                  </Badge>
                                  <Badge variant="outline" className="text-xs">
                                    Reputation: {item.reputation_score || 0}/100
                                  </Badge>
                                  {item.category && (
                                    <Badge variant="outline" className="text-xs">
                                      Category: {item.category}
                                    </Badge>
                                  )}
                                  {item.last_scan && (
                                    <p className="text-muted-foreground text-xs">Last scan: {item.last_scan}</p>
                                  )}
                                </div>
                              </div>
                            ))
                          ) : (
                            <div className="col-span-2 text-center py-8">
                              <p className="text-muted-foreground">No security data available</p>
                            </div>
                          )}
                        </div>
                      )}

                      {/* Default View (when no specific view is selected) */}
                      {!subdomainView && (
                        <div
                          className={`grid grid-cols-1 md:grid-cols-2 gap-3 max-h-96 overflow-y-auto ${subdomainScrollbar.showScrollbar ? 'scrollbar-show' : 'scrollbar-hide'}`}
                          onMouseEnter={subdomainScrollbar.handleMouseEnter}
                          onMouseLeave={subdomainScrollbar.handleMouseLeave}
                        >
                          {results.data.subdomains && results.data.subdomains.length > 0 ? (
                            results.data.subdomains.map((item: any, index: number) => (
                              <div
                                key={index}
                                className="p-4 bg-secondary rounded-xl border border-border hover:border-border transition-colors"
                              >
                                <div className="flex items-center justify-between mb-2">
                                  <p className="text-foreground font-medium text-sm break-all">{item.subdomain}</p>
                                  <Badge
                                    variant={item.status === "active" ? "default" : "secondary"}
                                    className="text-xs"
                                  >
                                    {item.status}
                                  </Badge>
                                </div>
                                <p className="text-muted-foreground text-xs">{item.ip}</p>
                                {item.type && (
                                  <Badge variant="outline" className="mt-2 text-xs">
                                    {item.type}
                                  </Badge>
                                )}
                              </div>
                            ))
                          ) : (
                            <div className="col-span-2 text-center py-8">
                              <p className="text-muted-foreground">No subdomains found</p>
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  )}

                  {results?.type === "whois" && (
                    <div>
                      <div className="flex items-center justify-between mb-4">
                        <h3 className="text-foreground font-medium text-lg flex items-center">
                          <Globe className="h-5 w-5 mr-2 text-blue-400" />
                          WHOIS Intelligence
                        </h3>
                        <Badge className="bg-blue-600 text-white">Domain Info</Badge>
                      </div>
                      {results.error && (
                        <div className="mb-4 p-3 bg-red-100 dark:bg-red-900/20 border border-red-300 dark:border-red-700 rounded-lg">
                          <p className="text-red-700 dark:text-red-300 text-sm">{results.error}</p>
                        </div>
                      )}
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        {/* Domain Information */}
                        {whoisView === 'domain' && (
                          <>
                            <div className="p-4 bg-secondary rounded-xl border border-border">
                              <p className="text-muted-foreground text-xs mb-1">Domain</p>
                              <p className="text-foreground font-medium">{results.data.domain}</p>
                            </div>
                            <div className="p-4 bg-secondary rounded-xl border border-border">
                              <p className="text-muted-foreground text-xs mb-1">Organization</p>
                              <p className="text-foreground font-medium">{results.data.organization}</p>
                            </div>
                            <div className="p-4 bg-secondary rounded-xl border border-border">
                              <p className="text-muted-foreground text-xs mb-1">Country</p>
                              <p className="text-foreground font-medium">{results.data.country}</p>
                            </div>
                            <div className="p-4 bg-secondary rounded-xl border border-border">
                              <p className="text-muted-foreground text-xs mb-1">State</p>
                              <p className="text-foreground font-medium">{results.data.state}</p>
                            </div>
                            <div className="p-4 bg-secondary rounded-xl border border-border">
                              <p className="text-muted-foreground text-xs mb-1">City</p>
                              <p className="text-foreground font-medium">{results.data.city}</p>
                            </div>
                            <div className="p-4 bg-secondary rounded-xl border border-border">
                              <p className="text-muted-foreground text-xs mb-1">Address</p>
                              <p className="text-foreground font-medium">{results.data.address}</p>
                            </div>
                          </>
                        )}
                        {/* Registrar Details */}
                        {whoisView === 'registrar' && (
                          <>
                            <div className="p-4 bg-secondary rounded-xl border border-border">
                              <p className="text-muted-foreground text-xs mb-1">Registrar</p>
                              <p className="text-foreground font-medium">{results.data.registrar}</p>
                            </div>
                            <div className="p-4 bg-secondary rounded-xl border border-border">
                              <p className="text-muted-foreground text-xs mb-1">Whois Server</p>
                              <p className="text-foreground font-medium">{results.data.whois_server}</p>
                            </div>
                            <div className="p-4 bg-secondary rounded-xl border border-border">
                              <p className="text-muted-foreground text-xs mb-1">Admin Email</p>
                              <p className="text-foreground font-medium">{results.data.admin_email}</p>
                            </div>
                            <div className="p-4 bg-secondary rounded-xl border border-border">
                              <p className="text-muted-foreground text-xs mb-1">Tech Email</p>
                              <p className="text-foreground font-medium">{results.data.tech_email}</p>
                            </div>
                            <div className="p-4 bg-secondary rounded-xl border border-border">
                              <p className="text-muted-foreground text-xs mb-1">Registrant Name</p>
                              <p className="text-foreground font-medium">{results.data.registrant_name}</p>
                            </div>
                            <div className="p-4 bg-secondary rounded-xl border border-border">
                              <p className="text-muted-foreground text-xs mb-1">Registrant Organization</p>
                              <p className="text-foreground font-medium">{results.data.registrant_organization}</p>
                            </div>
                            <div className="p-4 bg-secondary rounded-xl border border-border">
                              <p className="text-muted-foreground text-xs mb-1">Registrant Email</p>
                              <p className="text-foreground font-medium">{results.data.registrant_email}</p>
                            </div>
                          </>
                        )}
                        {/* Registration History */}
                        {whoisView === 'history' && (
                          <>
                            <div className="p-4 bg-secondary rounded-xl border border-border">
                              <p className="text-muted-foreground text-xs mb-1">Created</p>
                              <p className="text-foreground font-medium">{results.data.created}</p>
                            </div>
                            <div className="p-4 bg-secondary rounded-xl border border-border">
                              <p className="text-muted-foreground text-xs mb-1">Updated</p>
                              <p className="text-foreground font-medium">{results.data.updated}</p>
                            </div>
                            <div className="p-4 bg-secondary rounded-xl border border-border">
                              <p className="text-muted-foreground text-xs mb-1">Expires</p>
                              <p className="text-foreground font-medium">{results.data.expires}</p>
                            </div>
                            <div className="p-4 bg-secondary rounded-xl border border-border">
                              <p className="text-muted-foreground text-xs mb-1">Status</p>
                              <p className="text-foreground font-medium">{Array.isArray(results.data.status) ? results.data.status.join(', ') : results.data.status}</p>
                            </div>
                          </>
                        )}
                        {/* Nameserver Analysis */}
                        {whoisView === 'nameservers' && (
                          <>
                            <div className="p-4 bg-secondary rounded-xl border border-border">
                              <p className="text-muted-foreground text-xs mb-1">Nameservers</p>
                              <div className="flex flex-wrap gap-2">
                                {Array.isArray(results.data.nameservers) && results.data.nameservers.length > 0 ? (
                                  results.data.nameservers.map((ns: string, i: number) => (
                                    <Badge key={i} variant="outline" className="text-muted-foreground border-border text-xs">
                                      {ns}
                                    </Badge>
                                  ))
                                ) : (
                                  <span className="text-muted-foreground">No nameservers found</span>
                                )}
                              </div>
                            </div>
                            <div className="p-4 bg-secondary rounded-xl border border-border">
                              <p className="text-muted-foreground text-xs mb-1">DNSSEC</p>
                              <p className="text-foreground font-medium">{results.data.dnssec}</p>
                            </div>
                          </>
                        )}
                      </div>
                    </div>
                  )}

                  {results?.type === "dns" && (
                    <div>
                      <div className="flex items-center justify-between mb-4">
                        <h3 className="text-foreground font-medium text-lg flex items-center">
                          <Dns className="h-5 w-5 mr-2 text-green-400" />
                          DNS Records
                        </h3>
                        <div className="flex items-center space-x-2">
                          <Badge className="bg-green-600 text-white">
                            {results.data.records?.length || 0} records
                          </Badge>
                          {results.data.record_types_found && (
                            <Badge variant="outline" className="text-muted-foreground">
                              {results.data.record_types_found.length} types
                            </Badge>
                          )}
                        </div>
                      </div>
                      {results.error && (
                        <div className="mb-4 p-3 bg-red-100 dark:bg-red-900/20 border border-red-300 dark:border-red-700 rounded-lg">
                          <p className="text-red-700 dark:text-red-300 text-sm">{results.error}</p>
                        </div>
                      )}
                      <div
                        className={`space-y-3 max-h-96 overflow-y-auto ${dnsScrollbar.showScrollbar ? 'scrollbar-show' : 'scrollbar-hide'}`}
                        onMouseEnter={dnsScrollbar.handleMouseEnter}
                        onMouseLeave={dnsScrollbar.handleMouseLeave}
                      >
                        {results.data.records && results.data.records.length > 0 ? (
                          results.data.records.map((record: any, index: number) => (
                            <div
                              key={index}
                              className="p-4 bg-secondary rounded-xl border border-border hover:border-border transition-colors"
                            >
                              <div className="flex items-center justify-between mb-2">
                                <Badge variant="outline" className="border-green-500 text-green-400 text-xs">
                                  {record.type}
                                </Badge>
                                <div className="flex items-center space-x-2">
                                  {record.priority && (
                                    <Badge variant="outline" className="text-xs">
                                      Priority: {record.priority}
                                    </Badge>
                                  )}
                                  <span className="text-muted-foreground text-xs">TTL: {record.ttl}</span>
                                </div>
                              </div>
                              <p className="text-foreground text-sm break-all">{record.value}</p>
                            </div>
                          ))
                        ) : (
                          <div className="text-center py-8">
                            <p className="text-muted-foreground">No DNS records found</p>
                          </div>
                        )}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  )
}

