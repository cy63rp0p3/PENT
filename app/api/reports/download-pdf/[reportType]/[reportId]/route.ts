import { NextRequest, NextResponse } from 'next/server'

const DJANGO_BASE_URL = 'http://localhost:8000/api'

export async function POST(
  request: NextRequest,
  { params }: { params: { reportType: string; reportId: string } }
) {
  try {
    const { reportType, reportId } = params
    console.log('Downloading PDF report:', reportType, reportId)
    
    const response = await fetch(`${DJANGO_BASE_URL}/reports/${reportType}/${reportId}/download/`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
    })
    
    console.log('Backend response status:', response.status)
    
    if (!response.ok) {
      const errorText = await response.text()
      console.error('Backend error:', errorText)
      return NextResponse.json(
        { error: 'Failed to download report', details: errorText },
        { status: response.status }
      )
    }
    
    // Check if the response is a PDF (binary data)
    const contentType = response.headers.get('content-type')
    console.log('Response content type:', contentType)
    
    if (contentType && contentType.includes('application/pdf')) {
      // Handle PDF response
      const pdfBuffer = await response.arrayBuffer()
      console.log('PDF buffer size:', pdfBuffer.byteLength)
      
      return new NextResponse(pdfBuffer, {
        status: 200,
        headers: {
          'Content-Type': 'application/pdf',
          'Content-Disposition': `attachment; filename="${reportType}-report-${reportId}.pdf"`,
        },
      })
    } else {
      // Handle JSON response (error case)
      const data = await response.json()
      console.log('Backend download response:', data)
      return NextResponse.json(data)
    }
  } catch (error) {
    console.error('Download report API error:', error)
    return NextResponse.json(
      { error: 'Failed to download report' },
      { status: 500 }
    )
  }
} 