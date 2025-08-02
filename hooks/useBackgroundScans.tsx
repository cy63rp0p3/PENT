"use client"

import { createContext, useContext, useState, useEffect, ReactNode } from 'react'

interface ScanState {
  scanId: string
  target: string
  scanType: 'whois' | 'dns' | 'subdomain' | 'port_scan' | 'vulnerability_scan' | 'comprehensive_scan'
  toolType?: string
  scan_type?: string
  progress: number
  status: 'running' | 'completed' | 'cancelled' | 'error' | 'failed'
  startTime: number
  results?: any
  error?: string
  reportPromptShown?: boolean
}

interface BackgroundScansContextType {
  activeScans: ScanState[]
  startScan: (scanData: Omit<ScanState, 'startTime' | 'progress' | 'status'>) => void
  updateScanProgress: (scanId: string, progress: number, results?: any, error?: string) => void
  cancelScan: (scanId: string) => void
  removeScan: (scanId: string) => void
  getActiveScan: (scanId: string) => ScanState | undefined
}

const BackgroundScansContext = createContext<BackgroundScansContextType | undefined>(undefined)

export function BackgroundScansProvider({ children }: { children: ReactNode }) {
  const [activeScans, setActiveScans] = useState<ScanState[]>([])

  // Load scans from localStorage on mount
  useEffect(() => {
    const savedScans = localStorage.getItem('backgroundScans')
    if (savedScans) {
      try {
        const scans = JSON.parse(savedScans)
        setActiveScans(scans)
      } catch (error) {
        console.error('Failed to load background scans:', error)
      }
    }
  }, [])

  // Save scans to localStorage whenever they change
  useEffect(() => {
    try {
      // Clean up old scans to prevent localStorage quota issues
      const cleanedScans = activeScans.filter(scan => {
        // Keep only scans from the last 24 hours
        const oneDayAgo = Date.now() - (24 * 60 * 60 * 1000)
        return scan.startTime > oneDayAgo
      })
      
      // Limit to maximum 50 scans to prevent quota issues
      const limitedScans = cleanedScans.slice(-50)
      
      const dataToStore = JSON.stringify(limitedScans)
      
      // Check if data size is reasonable (under 4MB to be safe)
      if (dataToStore.length > 4 * 1024 * 1024) {
        console.warn('Background scans data too large, keeping only recent scans')
        // Keep only the 10 most recent scans
        const recentScans = cleanedScans.slice(-10)
        localStorage.setItem('backgroundScans', JSON.stringify(recentScans))
      } else {
        localStorage.setItem('backgroundScans', dataToStore)
      }
    } catch (error) {
      console.error('Failed to save background scans to localStorage:', error)
      // If localStorage is full, clear it and save only current scans
      try {
        localStorage.clear()
        localStorage.setItem('backgroundScans', JSON.stringify(activeScans.slice(-5)))
      } catch (clearError) {
        console.error('Failed to clear localStorage:', clearError)
      }
    }
  }, [activeScans])

  // Poll for scan progress in background
  useEffect(() => {
    const pollInterval = setInterval(async () => {
      const runningScans = activeScans.filter(scan => scan.status === 'running')
      
      if (runningScans.length > 0) {
        console.log(`Polling ${runningScans.length} running scans:`, runningScans.map(s => `${s.scanType}:${s.scanId}`))
      }
      
      for (const scan of runningScans) {
        try {
          // Use different endpoints for different scan types
          let endpoint = ''
          if (['whois', 'dns', 'subdomain'].includes(scan.scanType)) {
            endpoint = `http://localhost:8000/api/recon/progress/${scan.scanId}/`
          } else if (scan.scanType === 'port_scan') {
            endpoint = `http://localhost:8000/api/scan/nmap/status/${scan.scanId}/`
          } else if (scan.scanType === 'vulnerability_scan') {
            endpoint = `http://localhost:8000/api/scan/zap/status/${scan.scanId}/`
          } else if (scan.scanType === 'comprehensive_scan') {
            endpoint = `http://localhost:8000/api/scan/comprehensive/status/${scan.scanId}/`
          }
          
          if (endpoint) {
            const response = await fetch(endpoint)
            const data = await response.json()
            
            console.log(`Scan ${scan.scanId} progress:`, data)
            
            // Handle different response formats
            if (scan.scanType === 'port_scan') {
              // Nmap scan response format
              if (data.status === 'completed' && data.results) {
                updateScanProgress(scan.scanId, 100, data.results)
              } else if (data.status === 'failed') {
                updateScanProgress(scan.scanId, 0, undefined, data.error || 'Scan failed')
              } else if (data.progress !== undefined) {
                updateScanProgress(scan.scanId, data.progress)
              }
            } else if (scan.scanType === 'vulnerability_scan') {
              // Vulnerability scan response format
              if (data.status === 'completed' && data.results) {
                updateScanProgress(scan.scanId, 100, data.results)
              } else if (data.status === 'failed') {
                updateScanProgress(scan.scanId, 0, undefined, data.error || 'Scan failed')
              } else if (data.progress !== undefined) {
                updateScanProgress(scan.scanId, data.progress)
              }
            } else {
              // Other scan types response format
              if (data.progress >= 100) {
                updateScanProgress(scan.scanId, 100, data.result)
              } else {
                updateScanProgress(scan.scanId, data.progress)
              }
            }
          }
        } catch (error) {
          console.error(`Failed to poll scan ${scan.scanId}:`, error)
        }
      }
    }, 1000) // Poll every second

    return () => clearInterval(pollInterval)
  }, [activeScans])

  const startScan = (scanData: Omit<ScanState, 'startTime' | 'progress' | 'status'>) => {
    const newScan: ScanState = {
      ...scanData,
      startTime: Date.now(),
      progress: 0,
      status: 'running'
    }
    
    console.log('Starting new scan:', newScan)
    setActiveScans(prev => {
      const updated = [...prev, newScan]
      console.log('Updated active scans:', updated)
      return updated
    })
  }

  const updateScanProgress = (scanId: string, progress: number, results?: any, error?: string) => {
    setActiveScans(prev => prev.map(scan => {
      if (scan.scanId === scanId) {
        return {
          ...scan,
          progress,
          ...(results && { results }),
          ...(error && { error }),
          status: progress >= 100 ? 'completed' : scan.status
        }
      }
      return scan
    }))
  }

  const cancelScan = async (scanId: string) => {
    try {
      // Use different cancel endpoints based on scan type
      const scan = activeScans.find(s => s.scanId === scanId)
      let endpoint = ''
      
      if (scan?.scanType === 'port_scan') {
        endpoint = `http://localhost:8000/api/scan/nmap/cancel/${scanId}/`
      } else if (scan?.scanType === 'vulnerability_scan') {
        endpoint = `http://localhost:8000/api/scan/zap/cancel/${scanId}/`
      } else if (scan?.scanType === 'comprehensive_scan') {
        endpoint = `http://localhost:8000/api/scan/comprehensive/cancel/${scanId}/`
      } else {
        endpoint = `http://localhost:8000/api/recon/cancel/${scanId}/`
      }
      
      await fetch(endpoint, { method: 'POST' })
      setActiveScans(prev => prev.map(scan => 
        scan.scanId === scanId ? { ...scan, status: 'cancelled' } : scan
      ))
    } catch (error) {
      console.error('Failed to cancel scan:', error)
    }
  }

  const removeScan = (scanId: string) => {
    setActiveScans(prev => prev.filter(scan => scan.scanId !== scanId))
  }

  const getActiveScan = (scanId: string) => {
    return activeScans.find(scan => scan.scanId === scanId)
  }

  return (
    <BackgroundScansContext.Provider value={{
      activeScans,
      startScan,
      updateScanProgress,
      cancelScan,
      removeScan,
      getActiveScan
    }}>
      {children}
    </BackgroundScansContext.Provider>
  )
}

export function useBackgroundScans() {
  const context = useContext(BackgroundScansContext)
  if (context === undefined) {
    throw new Error('useBackgroundScans must be used within a BackgroundScansProvider')
  }
  return context
} 