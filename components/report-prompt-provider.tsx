"use client"

import { createContext, useContext, ReactNode } from "react"
import { useReportPrompt } from "@/hooks/useReportPrompt"
import ReportPrompt from "./report-prompt"

interface ReportPromptContextType {
  showReportPrompt: (scanResult: any) => void
  hideReportPrompt: () => void
}

const ReportPromptContext = createContext<ReportPromptContextType | undefined>(undefined)

export function useReportPromptContext() {
  const context = useContext(ReportPromptContext)
  if (context === undefined) {
    throw new Error('useReportPromptContext must be used within a ReportPromptProvider')
  }
  return context
}

interface ReportPromptProviderProps {
  children: ReactNode
}

export function ReportPromptProvider({ children }: ReportPromptProviderProps) {
  const {
    isOpen,
    scanResult,
    showReportPrompt,
    hideReportPrompt,
    handleSaveReport
  } = useReportPrompt()

  return (
    <ReportPromptContext.Provider value={{ showReportPrompt, hideReportPrompt }}>
      {children}
      
      {scanResult && (
        <ReportPrompt
          scanResult={scanResult}
          isOpen={isOpen}
          onClose={hideReportPrompt}
          onSave={handleSaveReport}
        />
      )}
    </ReportPromptContext.Provider>
  )
} 