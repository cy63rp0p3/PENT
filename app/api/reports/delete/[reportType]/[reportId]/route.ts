import { NextRequest, NextResponse } from 'next/server'

const DJANGO_BASE_URL = 'http://localhost:8000/api'

export async function DELETE(
  request: NextRequest,
  { params }: { params: { reportType: string; reportId: string } }
) {
  try {
    const { reportType, reportId } = params
    console.log('Deleting report:', reportType, reportId)
    
    const response = await fetch(`${DJANGO_BASE_URL}/reports/${reportType}/${reportId}/delete/`, {
      method: 'DELETE',
      headers: {
        'Content-Type': 'application/json',
      },
    })
    
    console.log('Backend response status:', response.status)
    
    if (!response.ok) {
      const errorText = await response.text()
      console.error('Backend error:', errorText)
      return NextResponse.json(
        { error: 'Failed to delete report', details: errorText },
        { status: response.status }
      )
    }
    
    const data = await response.json()
    console.log('Backend delete response:', data)
    return NextResponse.json(data)
  } catch (error) {
    console.error('Delete report API error:', error)
    return NextResponse.json(
      { error: 'Failed to delete report' },
      { status: 500 }
    )
  }
} 