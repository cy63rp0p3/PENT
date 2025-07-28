import type React from "react"
import { redirect } from "next/navigation"
import { createClient } from "@/lib/supabase"
import { SidebarProvider } from "@/components/ui/sidebar"
import { AppSidebar } from "@/components/app-sidebar"
import { DashboardHeader } from "@/components/dashboard-header"
import { SidebarInset } from "@/components/ui/sidebar"
import { BackgroundScansNotification } from "@/components/background-scans-notification"

export default async function DashboardLayout({
  children,
}: {
  children: React.ReactNode
}) {
  const supabase = createClient()
  const {
    data: { user },
  } = await supabase.auth.getUser()

  if (!user) {
    redirect("/auth/login")
  }

  return (
    <SidebarProvider>
      <AppSidebar />
      <SidebarInset>
        <DashboardHeader />
        <main className="flex-1 p-4 sm:p-6 overflow-auto">{children}</main>
        <BackgroundScansNotification />
      </SidebarInset>
    </SidebarProvider>
  )
}
