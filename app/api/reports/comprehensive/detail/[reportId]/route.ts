import { NextRequest, NextResponse } from 'next/server'

const DJANGO_BASE_URL = 'http://localhost:8000/api'

export async function GET(
  request: NextRequest,
  { params }: { params: { reportId: string } }
) {
  try {
    const reportId = params.reportId
    console.log('Fetching comprehensive report details for ID:', reportId)
    
    const response = await fetch(`${DJANGO_BASE_URL}/reports/comprehensive/${reportId}/`, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
      },
    })
    
    console.log('Backend response status:', response.status)
    
    if (!response.ok) {
      const errorText = await response.text()
      console.error('Backend error:', errorText)
      return NextResponse.json(
        { error: 'Failed to fetch comprehensive report details', details: errorText },
        { status: response.status }
      )
    }
    
    const data = await response.json()
    console.log('Backend comprehensive report details received:', data)
    return NextResponse.json(data)
  } catch (error) {
    console.error('Fetch comprehensive report details API error:', error)
    return NextResponse.json(
      { error: 'Failed to fetch comprehensive report details' },
      { status: 500 }
    )
  }
} 