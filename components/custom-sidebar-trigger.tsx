"use client"

import { Button } from "@/components/ui/button"
import { Menu } from "lucide-react"
import { useSidebar } from "@/components/ui/sidebar"

export function CustomSidebarTrigger() {
  const { toggleSidebar } = useSidebar()

  return (
    <Button
      variant="ghost"
      size="icon"
      onClick={toggleSidebar}
      className="h-8 w-8 text-muted-foreground hover:text-foreground hover:bg-accent border border-border bg-background transition-colors duration-200"
      style={{ borderRadius: '8px' }}
      aria-label="Toggle Sidebar"
    >
      <Menu className="h-4 w-4" />
    </Button>
  )
}
