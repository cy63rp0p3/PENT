import { NextRequest, NextResponse } from 'next/server'

const DJANGO_BASE_URL = 'http://localhost:8000/api'

export async function GET(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url)
    const action = searchParams.get('action')
    
    let url = ''
    
    switch (action) {
      case 'scan-results':
        url = `${DJANGO_BASE_URL}/reports/scan-results/`
        break
      case 'list':
        url = `${DJANGO_BASE_URL}/reports/list/`
        break
      default:
        return NextResponse.json({ error: 'Invalid action' }, { status: 400 })
    }
    
    const response = await fetch(url, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
      },
    })
    
    const data = await response.json()
    return NextResponse.json(data)
  } catch (error) {
    console.error('Reports API error:', error)
    return NextResponse.json(
      { error: 'Failed to fetch reports data' },
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
      case 'generate':
        url = `${DJANGO_BASE_URL}/reports/generate/`
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
    console.error('Reports API error:', error)
    return NextResponse.json(
      { error: 'Failed to process report request' },
      { status: 500 }
    )
  }
} 