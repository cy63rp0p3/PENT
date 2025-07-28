"use client"

import { useState, useEffect } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Progress } from '@/components/ui/progress'
import { X, Eye, Loader2, CheckCircle, XCircle, AlertCircle } from 'lucide-react'
import { useBackgroundScans } from '@/hooks/useBackgroundScans'
import { usePathname } from 'next/navigation'
import Link from 'next/link'

export function BackgroundScansNotification() {
  const { activeScans, cancelScan, removeScan } = useBackgroundScans()
  const [isExpanded, setIsExpanded] = useState(false)
  const [showCompletion, setShowCompletion] = useState(false)
  const [completedScan, setCompletedScan] = useState<any>(null)
  const [previousCompletedCount, setPreviousCompletedCount] = useState(0)
  const pathname = usePathname()

  const runningScans = activeScans.filter(scan => scan.status === 'running')
  const completedScans = activeScans.filter(scan => scan.status === 'completed')
  const cancelledScans = activeScans.filter(scan => scan.status === 'cancelled')

  // Check for newly completed scans
  useEffect(() => {
    if (completedScans.length > previousCompletedCount) {
      // A new scan was completed
      const newlyCompleted = completedScans[completedScans.length - 1] // Get the most recent completed scan
      setCompletedScan(newlyCompleted)
      setShowCompletion(true)
      setPreviousCompletedCount(completedScans.length)
      
      // Hide completion message after 3 seconds
      setTimeout(() => {
        setShowCompletion(false)
        setCompletedScan(null)
      }, 3000)
    }
  }, [completedScans, previousCompletedCount])

  // Don't show notification on reconnaissance page
  if (activeScans.length === 0 || pathname === '/dashboard/reconnaissance') return null

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'running':
        return <Loader2 className="h-4 w-4 animate-spin text-blue-500" />
      case 'completed':
        return <CheckCircle className="h-4 w-4 text-green-500" />
      case 'cancelled':
        return <XCircle className="h-4 w-4 text-red-500" />
      case 'error':
        return <AlertCircle className="h-4 w-4 text-yellow-500" />
      default:
        return <AlertCircle className="h-4 w-4 text-gray-500" />
    }
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'running':
        return 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200'
      case 'completed':
        return 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200'
      case 'cancelled':
        return 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200'
      case 'error':
        return 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200'
      default:
        return 'bg-gray-100 text-gray-800 dark:bg-gray-900 dark:text-gray-200'
    }
  }

  const formatDuration = (startTime: number) => {
    const duration = Date.now() - startTime
    const seconds = Math.floor(duration / 1000)
    const minutes = Math.floor(seconds / 60)
    
    if (minutes > 0) {
      return `${minutes}m ${seconds % 60}s`
    }
    return `${seconds}s`
  }

  return (
    <div className="fixed bottom-4 right-4 z-50 max-w-sm">
      {/* Completion Notification */}
      {showCompletion && completedScan && (
        <Card className="shadow-lg border-green-500 bg-green-50 dark:bg-green-900/20 mb-2">
          <CardContent className="p-3">
            <div className="flex items-center gap-2">
              <CheckCircle className="h-4 w-4 text-green-500" />
              <div className="flex-1">
                <p className="text-sm font-medium text-green-800 dark:text-green-200">
                  Scan Completed!
                </p>
                <p className="text-xs text-green-600 dark:text-green-300">
                  {completedScan.scanType} scan of {completedScan.target} finished successfully
                </p>
              </div>
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setShowCompletion(false)}
                className="h-6 w-6 p-0"
              >
                <X className="h-3 w-3" />
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Main Background Scans Card */}
      <Card className="shadow-lg border-border">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              {runningScans.length > 0 ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : completedScans.length > 0 ? (
                <CheckCircle className="h-4 w-4 text-green-500" />
              ) : (
                <Loader2 className="h-4 w-4 text-muted-foreground" />
              )}
              Background Scans
              {runningScans.length > 0 && (
                <Badge variant="secondary" className="text-xs">
                  {runningScans.length} running
                </Badge>
              )}
            </CardTitle>
            <div className="flex items-center gap-1">
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setIsExpanded(!isExpanded)}
                className="h-6 w-6 p-0"
              >
                {isExpanded ? <X className="h-3 w-3" /> : <Eye className="h-3 w-3" />}
              </Button>
            </div>
          </div>
        </CardHeader>

        {isExpanded && (
          <CardContent className="pt-0 space-y-3">
            {/* Running Scans */}
            {runningScans.map((scan) => (
              <div key={scan.scanId} className="p-3 bg-secondary rounded-lg border border-border">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2">
                    {getStatusIcon(scan.status)}
                    <span className="text-sm font-medium capitalize">
                      {scan.scanType} {scan.toolType && `(${scan.toolType})`}
                    </span>
                  </div>
                  <Button
                    variant="destructive"
                    size="sm"
                    onClick={() => cancelScan(scan.scanId)}
                    className="h-6 px-2 text-xs"
                  >
                    Cancel
                  </Button>
                </div>
                <p className="text-xs text-muted-foreground mb-2">{scan.target}</p>
                <div className="space-y-1">
                  <Progress value={scan.progress} className="h-1" />
                  <div className="flex justify-between text-xs text-muted-foreground">
                    <span>{scan.progress}%</span>
                    <span>{formatDuration(scan.startTime)}</span>
                  </div>
                </div>
              </div>
            ))}

            {/* Completed Scans */}
            {completedScans.slice(0, 3).map((scan) => (
              <div key={scan.scanId} className="p-3 bg-secondary rounded-lg border border-border">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2">
                    {getStatusIcon(scan.status)}
                    <span className="text-sm font-medium capitalize">
                      {scan.scanType} {scan.toolType && `(${scan.toolType})`}
                    </span>
                  </div>
                  <div className="flex items-center gap-1">
                    <Link href="/dashboard/reconnaissance">
                      <Button variant="outline" size="sm" className="h-6 px-2 text-xs">
                        View
                      </Button>
                    </Link>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => removeScan(scan.scanId)}
                      className="h-6 w-6 p-0"
                    >
                      <X className="h-3 w-3" />
                    </Button>
                  </div>
                </div>
                <p className="text-xs text-muted-foreground">{scan.target}</p>
                <Badge className={`text-xs mt-1 ${getStatusColor(scan.status)}`}>
                  Completed {formatDuration(scan.startTime)} ago
                </Badge>
              </div>
            ))}

            {/* Show more indicator */}
            {completedScans.length > 3 && (
              <div className="text-center">
                <Button variant="ghost" size="sm" className="text-xs">
                  +{completedScans.length - 3} more completed
                </Button>
              </div>
            )}

            {/* Clear all completed */}
            {completedScans.length > 0 && (
              <div className="pt-2 border-t border-border">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => completedScans.forEach(scan => removeScan(scan.scanId))}
                  className="w-full text-xs"
                >
                  Clear Completed
                </Button>
              </div>
            )}
          </CardContent>
        )}
      </Card>
    </div>
  )
} 