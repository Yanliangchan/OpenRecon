'use client'

import { useState } from 'react'
import * as XLSX from 'xlsx'
import { Upload, FileText, Send } from 'lucide-react'

interface ParsedData {
    fname: string
    lname: string
    phoneNumbers: string[]
    emails: string[]
    alt: string[]
}

export default function OpenReconUploader() {
    const [parsedData, setParsedData] = useState<ParsedData[]>([])
    const [error, setError] = useState('')
    const [fileName, setFileName] = useState('')

    const handleFileUpload = async (event: React.ChangeEvent<HTMLInputElement>) => {
        const file = event.target.files?.[0]
        if (file) {
            setFileName(file.name)
            try {
                const data = await file.arrayBuffer()
                const workbook = XLSX.read(data)
                const worksheet = workbook.Sheets[workbook.SheetNames[0]]
                const jsonData = XLSX.utils.sheet_to_json(worksheet)

                // Validate and format the data
                const formattedData: ParsedData[] = jsonData.map((row: any) => {
                    const phoneNumbers: string[] = []
                    const emails: string[] = []
                    const alt: string[] = []

                    // Parse phone numbers
                    for (let i = 1; i <= 5; i++) {
                        const phoneKey = `phone_number${i > 1 ? i : ''}`
                        if (row[phoneKey]) {
                            const phones = row[phoneKey].split(',').map((phone: string) => phone.trim())
                            phoneNumbers.push(...phones)
                        }
                    }

                    // Parse emails
                    for (let i = 1; i <= 5; i++) {
                        const emailKey = `email${i > 1 ? i : ''}`
                        if (row[emailKey]) {
                            const emailList = row[emailKey].split(',').map((email: string) => email.trim())
                            emails.push(...emailList)
                        }
                    }

                    // Parse alt
                    for (let i = 1; i <= 5; i++) {
                        const altKey = `alt${i > 1 ? i : ''}`
                        if (row[altKey]) {
                            const altList = row[altKey].split(',').map((altItem: string) => altItem.trim())
                            alt.push(...altList)
                        }
                    }

                    return {
                        fname: row.fname || '',
                        lname: row.lname || '',
                        phoneNumbers,
                        emails,
                        alt
                    }
                })

                setParsedData(formattedData)
                setError('')
            } catch (err) {
                console.error('Error parsing Excel file:', err)
                setError('Error parsing Excel file. Please make sure it\'s a valid Excel file with the correct columns.')
                setParsedData([])
            }
        }
    }

    const handleSubmit = async () => {
        if (parsedData.length === 0) {
            setError('Please upload and parse an Excel file first.')
            return
        }

        try {
            const response = await fetch('/api/process-data', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(parsedData),
            })

            if (response.ok) {
                alert('Data successfully sent to the backend!')
            } else {
                throw new Error('Failed to send data to the backend')
            }
        } catch (err) {
            console.error('Error sending data to backend:', err)
            setError('Error sending data to the backend. Please try again.')
        }
    }

    return (
        <div className="bg-gray-50 min-h-screen">
        <div className="max-w-7xl mx-auto py-12 px-4 sm:px-6 lg:px-8">
        <div className="max-w-3xl mx-auto">
        <div className="bg-white shadow sm:rounded-lg">
        <div className="px-4 py-5 sm:p-6">
        <h3 className="text-lg leading-6 font-medium text-gray-900">Upload Excel File</h3>
    <div className="mt-2 max-w-xl text-sm text-gray-500">
        <p>Upload your Excel file containing contact information.</p>
    </div>
    <div className="mt-5">
    <div className="mt-1 flex justify-center px-6 pt-5 pb-6 border-2 border-gray-300 border-dashed rounded-md">
    <div className="space-y-1 text-center">
    <Upload className="mx-auto h-12 w-12 text-gray-400" />
    <div className="flex text-sm text-gray-600">
    <label
        htmlFor="excelFile"
    className="relative cursor-pointer bg-white rounded-md font-medium text-indigo-600 hover:text-indigo-500 focus-within:outline-none focus-within:ring-2 focus-within:ring-offset-2 focus-within:ring-indigo-500"
        >
        <span>Upload a file</span>
    <input
    id="excelFile"
    name="excelFile"
    type="file"
    accept=".xlsx, .xls"
    className="sr-only"
    onChange={handleFileUpload}
    />
    </label>
    <p className="pl-1">or drag and drop</p>
    </div>
    <p className="text-xs text-gray-500">Excel files up to 10MB</p>
    </div>
    </div>
    {fileName && (
        <p className="mt-2 text-sm text-gray-500">
        <FileText className="inline-block mr-1 h-4 w-4" />
            {fileName}
            </p>
    )}
    </div>
    </div>
    </div>

    {error && (
        <div className="mt-4 bg-red-50 border-l-4 border-red-400 p-4">
        <div className="flex">
        <div className="flex-shrink-0">
        <svg className="h-5 w-5 text-red-400" viewBox="0 0 20 20" fill="currentColor">
    <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
        </svg>
        </div>
        <div className="ml-3">
    <p className="text-sm text-red-700">{error}</p>
        </div>
        </div>
        </div>
    )}

    {parsedData.length > 0 && (
        <div className="mt-8">
        <div className="bg-white shadow sm:rounded-lg">
        <div className="px-4 py-5 sm:p-6">
        <h3 className="text-lg leading-6 font-medium text-gray-900">Parsed Data Preview</h3>
    <div className="mt-5">
    <div className="flex flex-col">
    <div className="-my-2 overflow-x-auto sm:-mx-6 lg:-mx-8">
    <div className="py-2 align-middle inline-block min-w-full sm:px-6 lg:px-8">
    <div className="shadow overflow-hidden border-b border-gray-200 sm:rounded-lg">
    <table className="min-w-full divide-y divide-gray-200">
    <thead className="bg-gray-50">
    <tr>
        <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Name</th>
        <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Phone Numbers</th>
    <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Emails</th>
        <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Alt</th>
        </tr>
        </thead>
        <tbody className="bg-white divide-y divide-gray-200">
        {parsedData.map((row, i) => (
                <tr key={i}>
                <td className="px-6 py-4 whitespace-nowrap">
                <div className="text-sm font-medium text-gray-900">{row.fname} {row.lname}</div>
    </td>
    <td className="px-6 py-4 whitespace-nowrap">
    <div className="text-sm text-gray-500">{row.phoneNumbers.join(', ')}</div>
        </td>
        <td className="px-6 py-4 whitespace-nowrap">
    <div className="text-sm text-gray-500">{row.emails.join(', ')}</div>
        </td>
        <td className="px-6 py-4 whitespace-nowrap">
    <div className="text-sm text-gray-500">{row.alt.join(', ')}</div>
        </td>
        </tr>
    ))}
        </tbody>
        </table>
        </div>
        </div>
        </div>
        </div>
        </div>
        </div>
        </div>

        <div className="mt-8 bg-white shadow sm:rounded-lg">
    <div className="px-4 py-5 sm:p-6">
    <h3 className="text-lg leading-6 font-medium text-gray-900">JSON Preview</h3>
    <div className="mt-2 max-w-xl text-sm text-gray-500">
        <p>This is how the data will be sent to the backend.</p>
    </div>
    <div className="mt-5">
    <pre className="bg-gray-100 p-4 rounded-md overflow-x-auto text-xs">
        {JSON.stringify(parsedData, null, 2)}
        </pre>
        </div>
        </div>
        </div>

        <div className="mt-8 flex justify-end">
    <button
        onClick={handleSubmit}
        className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500"
        >
        <Send className="mr-2 h-4 w-4" />
            Submit Data
    </button>
    </div>
    </div>
    )}
    </div>
    </div>
    </div>
)
}

