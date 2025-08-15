import { NextRequest, NextResponse } from 'next/server'

const DJANGO_BASE_URL = 'http://localhost:8000/api'

export async function POST(request: NextRequest) {
  try {
    const body = await request.json()
    console.log('Generating comprehensive report with data:', body)
    
    const response = await fetch(`${DJANGO_BASE_URL}/reports/comprehensive/generate/`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(body),
    })
    
    console.log('Backend response status:', response.status)
    
    if (!response.ok) {
      const errorText = await response.text()
      console.error('Backend error:', errorText)
      return NextResponse.json(
        { error: 'Failed to generate comprehensive report', details: errorText },
        { status: response.status }
      )
    }
    
    const data = await response.json()
    console.log('Backend comprehensive report generation response:', data)
    return NextResponse.json(data)
  } catch (error) {
    console.error('Generate comprehensive report API error:', error)
    return NextResponse.json(
      { error: 'Failed to generate comprehensive report' },
      { status: 500 }
    )
  }
} 