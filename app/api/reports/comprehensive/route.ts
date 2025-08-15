import { NextRequest, NextResponse } from 'next/server'

const DJANGO_BASE_URL = 'http://localhost:8000/api'

export async function GET(request: NextRequest) {
  try {
    const response = await fetch(`${DJANGO_BASE_URL}/reports/comprehensive/`, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
      },
    })
    
    if (!response.ok) {
      const errorText = await response.text()
      console.error('Backend error:', errorText)
      return NextResponse.json(
        { error: 'Failed to fetch comprehensive reports', details: errorText },
        { status: response.status }
      )
    }
    
    const data = await response.json()
    return NextResponse.json(data)
  } catch (error) {
    console.error('Fetch comprehensive reports API error:', error)
    return NextResponse.json(
      { error: 'Failed to fetch comprehensive reports' },
      { status: 500 }
    )
  }
} 