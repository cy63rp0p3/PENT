import { NextRequest, NextResponse } from 'next/server'

const DJANGO_BASE_URL = process.env.DJANGO_BASE_URL || 'http://localhost:8000/api'

export async function GET(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url)
    
    // Forward all query parameters to Django
    const queryString = searchParams.toString()
    const url = `${DJANGO_BASE_URL}/audit-logs/statistics/${queryString ? `?${queryString}` : ''}`
    
    const response = await fetch(url, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
      },
    })
    
    const data = await response.json()
    return NextResponse.json(data)
  } catch (error) {
    console.error('Audit logs statistics API error:', error)
    return NextResponse.json(
      { error: 'Failed to fetch audit logs statistics' },
      { status: 500 }
    )
  }
} 