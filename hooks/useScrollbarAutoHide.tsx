import { useEffect, useRef, useState } from "react"

export function useScrollbarAutoHide(timeout = 2000) {
  const [showScrollbar, setShowScrollbar] = useState(true)
  const timer = useRef<NodeJS.Timeout | null>(null)

  const handleMouseEnter = () => {
    setShowScrollbar(true)
    if (timer.current) clearTimeout(timer.current)
  }

  const handleMouseLeave = () => {
    timer.current = setTimeout(() => setShowScrollbar(false), timeout)
  }

  useEffect(() => {
    setShowScrollbar(true)
    timer.current = setTimeout(() => setShowScrollbar(false), timeout)
    return () => {
      if (timer.current) clearTimeout(timer.current)
    }
  }, [timeout])

  return { showScrollbar, handleMouseEnter, handleMouseLeave }
} 