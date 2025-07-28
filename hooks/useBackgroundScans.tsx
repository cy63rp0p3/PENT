"use client"

import { createContext, useContext, useState, useEffect, ReactNode } from 'react'

interface ScanState {
  scanId: string
  target: string
  scanType: 'whois' | 'dns' | 'subdomain' | 'port_scan' | 'vulnerability_scan'
  toolType?: string
  scan_type?: string
  progress: number
  status: 'running' | 'completed' | 'cancelled' | 'error' | 'failed'
  startTime: number
  results?: any
  error?: string
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
    localStorage.setItem('backgroundScans', JSON.stringify(activeScans))
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
          } else if (['port_scan', 'vulnerability_scan'].includes(scan.scanType)) {
            endpoint = `http://localhost:8000/api/recon/progress/${scan.scanId}/`
          }
          
          if (endpoint) {
            const response = await fetch(endpoint)
            const data = await response.json()
            
            console.log(`Scan ${scan.scanId} progress:`, data.progress)
            
            if (data.progress >= 100) {
              updateScanProgress(scan.scanId, 100, data.result)
            } else {
              updateScanProgress(scan.scanId, data.progress)
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
      await fetch(`http://localhost:8000/api/recon/cancel/${scanId}/`, { method: 'POST' })
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