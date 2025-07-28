import { NextRequest, NextResponse } from 'next/server'

const DJANGO_BASE_URL = 'http://localhost:8000/api'

export async function GET(
  request: NextRequest,
  { params }: { params: { id: string } }
) {
  try {
    const reportId = params.id
    
    const response = await fetch(`${DJANGO_BASE_URL}/reports/detail/${reportId}/`, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
      },
    })
    
    const data = await response.json()
    return NextResponse.json(data)
  } catch (error) {
    console.error('Report detail API error:', error)
    return NextResponse.json(
      { error: 'Failed to fetch report details' },
      { status: 500 }
    )
  }
} 