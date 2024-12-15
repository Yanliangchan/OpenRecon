import { NextResponse } from 'next/server'

export async function POST(request: Request) {
    const data = await request.json()

    // Process the data here (e.g., save to database, perform OSINT operations, etc.)
    console.log('Received data:', data)

    // Return a response
    return NextResponse.json({ success: true })
}

