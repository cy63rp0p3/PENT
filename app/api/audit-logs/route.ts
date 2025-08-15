import { NextRequest, NextResponse } from 'next/server'

const DJANGO_BASE_URL = process.env.DJANGO_BASE_URL || 'http://localhost:8000/api'

export async function GET(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url)
    
    // Forward all query parameters to Django
    const queryString = searchParams.toString()
    const url = `${DJANGO_BASE_URL}/audit-logs/${queryString ? `?${queryString}` : ''}`
    
    const response = await fetch(url, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
      },
    })
    
    const data = await response.json()
    return NextResponse.json(data)
  } catch (error) {
    console.error('Audit logs API error:', error)
    return NextResponse.json(
      { error: 'Failed to fetch audit logs' },
      { status: 500 }
    )
  }
}

export async function POST(request: NextRequest) {
  try {
    const body = await request.json()
    const { action, ...data } = body
    
    let url = ''
    
    switch (action) {
      case 'export':
        url = `${DJANGO_BASE_URL}/audit-logs/export/`
        break
      case 'clear':
        url = `${DJANGO_BASE_URL}/audit-logs/clear/`
        break
      default:
        return NextResponse.json({ error: 'Invalid action' }, { status: 400 })
    }
    
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(data),
    })
    
    const responseData = await response.json()
    return NextResponse.json(responseData)
  } catch (error) {
    console.error('Audit logs API error:', error)
    return NextResponse.json(
      { error: 'Failed to process audit logs request' },
      { status: 500 }
    )
  }
} 