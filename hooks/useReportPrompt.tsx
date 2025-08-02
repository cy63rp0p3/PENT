"use client"

import { useState, useCallback } from "react"

interface ScanResult {
  scan_type: string
  target: string
  results: any
  scan_id: string
  timestamp: string
  status: string
}

interface ReportPromptState {
  isOpen: boolean
  scanResult: ScanResult | null
}

export function useReportPrompt() {
  const [state, setState] = useState<ReportPromptState>({
    isOpen: false,
    scanResult: null
  })

  const showReportPrompt = useCallback((scanResult: ScanResult) => {
    setState({
      isOpen: true,
      scanResult
    })
  }, [])

  const hideReportPrompt = useCallback(() => {
    setState({
      isOpen: false,
      scanResult: null
    })
  }, [])

  const handleSaveReport = useCallback((reportData: any) => {
    // This will be called when a report is successfully saved
    console.log('Report saved:', reportData)
    // You can add additional logic here, like showing a notification
  }, [])

  return {
    isOpen: state.isOpen,
    scanResult: state.scanResult,
    showReportPrompt,
    hideReportPrompt,
    handleSaveReport
  }
} 