import type { Metadata } from 'next'
import { GeistSans } from 'geist/font/sans'
import { GeistMono } from 'geist/font/mono'
import './globals.css'
import { BackgroundScansProvider } from '@/hooks/useBackgroundScans'
import { ReportPromptProvider } from '@/components/report-prompt-provider'

export const metadata: Metadata = {
  title: 'PEN-T',
  icons: {
    icon: '/favicon.svg',
  },
}

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode
}>) {
  return (
    <html lang="en">
      <head>
        <style>{`
html {
  font-family: ${GeistSans.style.fontFamily};
  --font-sans: ${GeistSans.variable};
  --font-mono: ${GeistMono.variable};
}
        `}</style>
      </head>
      <body>
        <BackgroundScansProvider>
          <ReportPromptProvider>
            {children}
          </ReportPromptProvider>
        </BackgroundScansProvider>
      </body>
    </html>
  )
}
