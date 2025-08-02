"use client"

import { useState, useEffect } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { 
  AlertTriangle, 
  Download, 
  Network, 
  CheckCircle, 
  XCircle,
  ExternalLink,
  Info,
  Zap
} from "lucide-react"

interface NmapDetectionProps {
  onUseBasicScanner: () => void
  onNmapAvailable: () => void
  children: React.ReactNode
}

interface NmapStatus {
  available: boolean
  version?: string
  error?: string
}

export default function NmapDetection({ onUseBasicScanner, onNmapAvailable, children }: NmapDetectionProps) {
  const [nmapStatus, setNmapStatus] = useState<NmapStatus>({ available: false })
  const [checking, setChecking] = useState(true)
  const [showDownloadInfo, setShowDownloadInfo] = useState(false)

  useEffect(() => {
    checkNmapAvailability()
  }, [])

  const checkNmapAvailability = async () => {
    setChecking(true)
    try {
      const response = await fetch('http://localhost:8000/api/scan/check-nmap/', {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
        },
      })
      
      const data = await response.json()
      
      if (data.success) {
        setNmapStatus({
          available: true,
          version: data.version
        })
        onNmapAvailable()
      } else {
        setNmapStatus({
          available: false,
          error: data.error || 'Nmap not found'
        })
      }
    } catch (error) {
      console.error('Error checking Nmap availability:', error)
      setNmapStatus({
        available: false,
        error: 'Failed to check Nmap availability'
      })
    } finally {
      setChecking(false)
    }
  }

  const handleDownloadNmap = () => {
    setShowDownloadInfo(true)
  }

  const getDownloadLink = () => {
    // Custom Nmap download link
    return "https://drive.google.com/file/d/1Pd3xQI93jEGrLL3Qq3J40_xDBcWm4b0_/view?usp=drive_link"
  }

  if (checking) {
    return (
      <div className="flex items-center justify-center p-8">
        <div className="text-center">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 mx-auto mb-4"></div>
          <p className="text-muted-foreground">Checking Nmap availability...</p>
        </div>
      </div>
    )
  }

  if (nmapStatus.available) {
    return <>{children}</>
  }

  return (
    <div className="space-y-6">
      <Alert className="border-orange-500 bg-orange-50 dark:bg-orange-900/20">
        <AlertTriangle className="h-4 w-4 text-orange-500" />
        <AlertDescription className="text-orange-700 dark:text-orange-300">
          Nmap is not available on your system. You can either use the basic port scanner or install Nmap for advanced scanning capabilities.
        </AlertDescription>
      </Alert>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Basic Scanner Option */}
        <Card className="border-green-500 bg-green-50 dark:bg-green-900/20">
          <CardHeader>
            <div className="flex items-center gap-2">
              <Network className="h-5 w-5 text-green-600" />
              <CardTitle className="text-green-800 dark:text-green-200">Basic Port Scanner</CardTitle>
            </div>
            <CardDescription className="text-green-700 dark:text-green-300">
              Use our built-in basic port scanner for simple port detection
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <div className="flex items-center gap-2">
                <CheckCircle className="h-4 w-4 text-green-600" />
                <span className="text-sm text-green-700 dark:text-green-300">No installation required</span>
              </div>
              <div className="flex items-center gap-2">
                <CheckCircle className="h-4 w-4 text-green-600" />
                <span className="text-sm text-green-700 dark:text-green-300">Quick port detection</span>
              </div>
              <div className="flex items-center gap-2">
                <CheckCircle className="h-4 w-4 text-green-600" />
                <span className="text-sm text-green-700 dark:text-green-300">Basic service identification</span>
              </div>
            </div>
            
            <div className="flex items-center gap-2">
              <Badge variant="outline" className="text-green-600 border-green-600">
                <Zap className="h-3 w-3 mr-1" />
                Recommended for quick scans
              </Badge>
            </div>

            <Button 
              onClick={onUseBasicScanner}
              className="w-full bg-green-600 hover:bg-green-700 text-white"
            >
              <Network className="h-4 w-4 mr-2" />
              Use Basic Scanner
            </Button>
          </CardContent>
        </Card>

        {/* Nmap Installation Option */}
        <Card className="border-blue-500 bg-blue-50 dark:bg-blue-900/20">
          <CardHeader>
            <div className="flex items-center gap-2">
              <Download className="h-5 w-5 text-blue-600" />
              <CardTitle className="text-blue-800 dark:text-blue-200">Install Nmap</CardTitle>
            </div>
            <CardDescription className="text-blue-700 dark:text-blue-300">
              Install Nmap for advanced scanning capabilities and detailed results
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <div className="flex items-center gap-2">
                <CheckCircle className="h-4 w-4 text-blue-600" />
                <span className="text-sm text-blue-700 dark:text-blue-300">Advanced port scanning</span>
              </div>
              <div className="flex items-center gap-2">
                <CheckCircle className="h-4 w-4 text-blue-600" />
                <span className="text-sm text-blue-700 dark:text-blue-300">OS detection</span>
              </div>
              <div className="flex items-center gap-2">
                <CheckCircle className="h-4 w-4 text-blue-600" />
                <span className="text-sm text-blue-700 dark:text-blue-300">Service version detection</span>
              </div>
              <div className="flex items-center gap-2">
                <CheckCircle className="h-4 w-4 text-blue-600" />
                <span className="text-sm text-blue-700 dark:text-blue-300">Script scanning</span>
              </div>
            </div>

            <div className="flex items-center gap-2">
              <Badge variant="outline" className="text-blue-600 border-blue-600">
                <Info className="h-3 w-3 mr-1" />
                Requires installation
              </Badge>
            </div>

            <Button 
              onClick={handleDownloadNmap}
              className="w-full bg-blue-600 hover:bg-blue-700 text-white"
            >
              <Download className="h-4 w-4 mr-2" />
              Download Nmap
            </Button>
          </CardContent>
        </Card>
      </div>

      {/* Download Information Modal */}
      {showDownloadInfo && (
        <Card className="border-2 border-blue-500">
          <CardHeader>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Download className="h-5 w-5 text-blue-600" />
                <CardTitle>Download Nmap</CardTitle>
              </div>
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setShowDownloadInfo(false)}
              >
                <XCircle className="h-4 w-4" />
              </Button>
            </div>
            <CardDescription>
              Follow these steps to install Nmap and enable advanced scanning features
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-3">
              <div className="p-3 bg-blue-100 dark:bg-blue-900/30 rounded-lg">
                <h4 className="font-semibold text-blue-800 dark:text-blue-200 mb-2">Step 1: Download Nmap</h4>
                <p className="text-sm text-blue-700 dark:text-blue-300 mb-2">
                  Visit the official Nmap download page and download the appropriate version for your operating system.
                </p>
                <Button 
                  asChild
                  className="bg-blue-600 hover:bg-blue-700 text-white"
                >
                  <a href={getDownloadLink()} target="_blank" rel="noopener noreferrer">
                    <ExternalLink className="h-4 w-4 mr-2" />
                    Download Nmap
                  </a>
                </Button>
              </div>

              <div className="p-3 bg-green-100 dark:bg-green-900/30 rounded-lg">
                <h4 className="font-semibold text-green-800 dark:text-green-200 mb-2">Step 2: Install Nmap</h4>
                <div className="text-sm text-green-700 dark:text-green-300 space-y-1">
                  <p><strong>Windows:</strong> Run the installer and follow the setup wizard</p>
                  <p><strong>macOS:</strong> Use Homebrew: <code className="bg-green-200 dark:bg-green-800 px-1 rounded">brew install nmap</code></p>
                  <p><strong>Linux:</strong> Use package manager: <code className="bg-green-200 dark:bg-green-800 px-1 rounded">sudo apt install nmap</code></p>
                </div>
              </div>

              <div className="p-3 bg-purple-100 dark:bg-purple-900/30 rounded-lg">
                <h4 className="font-semibold text-purple-800 dark:text-purple-200 mb-2">Step 3: Verify Installation</h4>
                <p className="text-sm text-purple-700 dark:text-purple-300 mb-2">
                  After installation, restart your application and the advanced scanning features will be available.
                </p>
                <Button 
                  onClick={() => {
                    setShowDownloadInfo(false)
                    checkNmapAvailability()
                  }}
                  className="bg-purple-600 hover:bg-purple-700 text-white"
                >
                  <CheckCircle className="h-4 w-4 mr-2" />
                  Check Again
                </Button>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Current Status */}
      <Card className="bg-gray-50 dark:bg-gray-900/50">
        <CardContent className="pt-6">
          <div className="flex items-center gap-2">
            <XCircle className="h-4 w-4 text-red-500" />
            <span className="text-sm text-muted-foreground">
              Current Status: Nmap not available
            </span>
          </div>
          {nmapStatus.error && (
            <p className="text-xs text-red-500 mt-1">{nmapStatus.error}</p>
          )}
        </CardContent>
      </Card>
    </div>
  )
} 