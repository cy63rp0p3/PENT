# 🚀 Proactive Reporting System

## Overview

The proactive reporting system automatically prompts users to save scan results as individual reports after each reconnaissance, scanning, or exploitation activity. Users can then combine multiple individual reports into comprehensive PDF reports.

## 🎯 Key Features

### 1. **Automatic Report Prompts**
- After each scan completes, users are prompted to save results as a report
- Prompt shows scan summary, severity, and findings count
- Users can customize report title or skip saving

### 2. **Individual Report Management**
- View all saved individual reports
- Download individual reports as PDF
- Delete unwanted reports
- View detailed report information

### 3. **Comprehensive Report Generation**
- Select multiple individual reports to combine
- Generate comprehensive security assessments
- Download comprehensive reports as PDF
- Automatic severity calculation and risk assessment

### 4. **Smart Severity Calculation**
- Automatic severity assessment based on findings
- Different logic for each scan type:
  - **Vulnerability Scans**: Based on critical/high/medium/low counts
  - **Port Scans**: Based on number of open ports
  - **Subdomain Scans**: Based on number of subdomains found
  - **DNS Scans**: Always low severity (informational)

## 🏗️ System Architecture

### Frontend Components

#### 1. **ReportPrompt Component** (`components/report-prompt.tsx`)
```typescript
// Modal dialog that appears after scan completion
<ReportPrompt
  scanResult={scanData}
  isOpen={true}
  onClose={hidePrompt}
  onSave={handleSaveReport}
/>
```

#### 2. **ReportPromptProvider** (`components/report-prompt-provider.tsx`)
```typescript
// Global provider for report prompt state
<ReportPromptProvider>
  <App />
</ReportPromptProvider>
```

#### 3. **useReportPrompt Hook** (`hooks/useReportPrompt.tsx`)
```typescript
// Hook to manage report prompt state
const { showReportPrompt, hideReportPrompt } = useReportPromptContext()
```

### Backend API Endpoints

#### Individual Reports
- `GET /api/reports/individual/` - List all individual reports
- `POST /api/reports/save-individual/` - Save new individual report
- `GET /api/reports/individual/{id}/` - Get individual report details
- `DELETE /api/reports/individual/{id}/` - Delete individual report

#### Comprehensive Reports
- `GET /api/reports/comprehensive/` - List all comprehensive reports
- `POST /api/reports/comprehensive/generate/` - Generate comprehensive report
- `DELETE /api/reports/comprehensive/{id}/` - Delete comprehensive report

#### PDF Downloads
- `POST /api/reports/{type}/{id}/download/` - Download report as PDF

## 🔧 Integration Guide

### Step 1: Add Report Prompt Provider

Update your root layout to include the report prompt provider:

```typescript
// app/layout.tsx
import { ReportPromptProvider } from '@/components/report-prompt-provider'

export default function RootLayout({ children }) {
  return (
    <html>
      <body>
        <ReportPromptProvider>
          {children}
        </ReportPromptProvider>
      </body>
    </html>
  )
}
```

### Step 2: Integrate into Scan Pages

Add the report prompt trigger to your scan pages:

```typescript
// In your scan page component
import { useReportPromptContext } from '@/components/report-prompt-provider'

export default function ScanPage() {
  const { showReportPrompt } = useReportPromptContext()
  
  // After scan completes
  const handleScanComplete = (scanResults) => {
    showReportPrompt({
      scan_type: 'vulnerability_scan',
      target: 'example.com',
      results: scanResults,
      scan_id: 'scan_123',
      timestamp: new Date().toISOString(),
      status: 'completed'
    })
  }
}
```

### Step 3: Update Background Scans Hook

The background scans hook automatically detects completed scans and shows prompts:

```typescript
// hooks/useBackgroundScans.tsx
useEffect(() => {
  activeScans.forEach(scan => {
    if (scan.status === 'completed' && scan.results && !scan.reportPromptShown) {
      scan.reportPromptShown = true
      showReportPrompt({
        scan_type: scan.scanType,
        target: scan.target,
        results: scan.results,
        scan_id: scan.scanId,
        timestamp: new Date().toISOString(),
        status: 'completed'
      })
    }
  })
}, [activeScans, showReportPrompt])
```

## 📊 Report Data Structure

### Individual Report
```typescript
interface IndividualReport {
  id: string
  title: string
  scan_type: string
  target: string
  timestamp: string
  status: string
  severity: string
  summary: string
  details: any
  findings_count: number
}
```

### Comprehensive Report
```typescript
interface ComprehensiveReport {
  id: string
  title: string
  generated_at: string
  included_reports: string[]
  total_findings: number
  overall_severity: string
  status: 'draft' | 'generated' | 'downloaded'
  executive_summary: any
  findings: any[]
  recommendations: any[]
  risk_assessment: any
}
```

## 🎨 User Interface

### Reports Page Tabs

1. **Individual Reports Tab**
   - List of all saved individual reports
   - Filter by scan type, severity, target
   - View details, download PDF, delete

2. **Comprehensive Reports Tab**
   - List of all generated comprehensive reports
   - Download comprehensive PDF reports
   - Delete comprehensive reports

3. **Generate Report Tab**
   - Select multiple individual reports
   - Enter comprehensive report title
   - Generate comprehensive assessment

### Report Prompt Modal

- **Scan Summary**: Shows scan type, target, findings count, severity
- **Report Title**: Editable title with auto-generated default
- **Action Buttons**: Save Report or Skip

## 🔄 Workflow

### Individual Report Workflow
1. User runs a scan (reconnaissance, scanning, exploitation)
2. Scan completes and results are available
3. Report prompt automatically appears
4. User can:
   - Save results as individual report (with custom title)
   - Skip saving the report
5. Saved reports appear in Individual Reports tab

### Comprehensive Report Workflow
1. User navigates to Reports page
2. Goes to "Generate Report" tab
3. Selects multiple individual reports to include
4. Enters comprehensive report title
5. Clicks "Generate Comprehensive Report"
6. Comprehensive report is created and appears in Comprehensive Reports tab
7. User can download comprehensive report as PDF

## 🛠️ Customization

### Adding New Scan Types

1. **Update Scan Type Names**:
```typescript
// In report-prompt.tsx
const getScanTypeName = (type: string) => {
  switch (type) {
    case 'new_scan_type':
      return 'New Scan Type Name'
    // ... existing cases
  }
}
```

2. **Update Severity Calculation**:
```typescript
// In report-prompt.tsx
const calculateSeverity = () => {
  if (scan_type === 'new_scan_type') {
    // Add your severity logic
    return 'Medium'
  }
  // ... existing logic
}
```

3. **Update Findings Count**:
```typescript
// In report-prompt.tsx
const getFindingsCount = () => {
  if (scan_type === 'new_scan_type') {
    return results?.new_findings?.length || 0
  }
  // ... existing logic
}
```

### Customizing Report Content

The backend includes helper functions for generating report content:

- `generate_scan_summary()` - Creates summary text
- `generate_comprehensive_executive_summary()` - Executive summary
- `extract_comprehensive_findings()` - Extracts findings from reports
- `generate_comprehensive_recommendations()` - Security recommendations
- `generate_comprehensive_risk_assessment()` - Risk assessment

## 🚀 Usage Examples

### Example 1: Vulnerability Scan
```typescript
// After vulnerability scan completes
showReportPrompt({
  scan_type: 'vulnerability_scan',
  target: 'example.com',
  results: {
    critical_vulnerabilities: [...],
    high_vulnerabilities: [...],
    medium_vulnerabilities: [...],
    low_vulnerabilities: [...]
  },
  scan_id: 'vuln_123',
  timestamp: new Date().toISOString(),
  status: 'completed'
})
```

### Example 2: Port Scan
```typescript
// After port scan completes
showReportPrompt({
  scan_type: 'port_scan',
  target: 'example.com',
  results: {
    open_ports: [...],
    closed_ports: [...],
    filtered_ports: [...]
  },
  scan_id: 'port_123',
  timestamp: new Date().toISOString(),
  status: 'completed'
})
```

### Example 3: Subdomain Enumeration
```typescript
// After subdomain scan completes
showReportPrompt({
  scan_type: 'subdomain',
  target: 'example.com',
  results: {
    subdomains: [...],
    ssl_info: {...},
    reputation: {...}
  },
  scan_id: 'sub_123',
  timestamp: new Date().toISOString(),
  status: 'completed'
})
```

## 🔍 Testing

Use the example component to test the system:

```typescript
// components/scan-integration-example.tsx
import ScanIntegrationExample from '@/components/scan-integration-example'

// Add to any page for testing
<ScanIntegrationExample />
```

This component simulates different scan types and triggers the report prompt system.

## 📝 Notes

- Individual reports are stored in cache for 7 days
- Comprehensive reports are stored in cache for 30 days
- PDF generation is currently a placeholder (returns success message)
- The system automatically calculates severity and findings counts
- Report prompts only show once per completed scan

## 🎉 Benefits

1. **Proactive Reporting**: Users are reminded to save results immediately
2. **Organized Workflow**: Clear separation between individual and comprehensive reports
3. **Flexible Selection**: Choose which reports to include in comprehensive assessments
4. **Professional Output**: Structured reports with executive summaries and recommendations
5. **Easy Integration**: Simple hook-based integration into existing scan pages 