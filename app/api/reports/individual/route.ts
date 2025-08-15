import { NextRequest, NextResponse } from 'next/server'

const DJANGO_BASE_URL = 'http://localhost:8000/api'

export async function GET(request: NextRequest) {
  try {
    console.log('Fetching individual reports from backend...')
    const response = await fetch(`${DJANGO_BASE_URL}/reports/individual/`, {
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
        { error: 'Failed to fetch individual reports', details: errorText },
        { status: response.status }
      )
    }
    
    const data = await response.json()
    console.log('Backend data received:', data)
    return NextResponse.json(data)
  } catch (error) {
    console.error('Fetch individual reports API error:', error)
    return NextResponse.json(
      { error: 'Failed to fetch individual reports' },
      { status: 500 }
    )
  }
} 