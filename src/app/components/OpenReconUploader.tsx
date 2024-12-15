'use client'

import { useState } from 'react'
import * as XLSX from 'xlsx'
import { Upload, FileText, Send, ChevronDown, ChevronUp, Download } from 'lucide-react'

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
    const [showJsonPreview, setShowJsonPreview] = useState(false)
    const [showParsedDataPreview, setShowParsedDataPreview] = useState(false)
    const [currentPage, setCurrentPage] = useState(1)
    const [activeView, setActiveView] = useState<'input' | 'output'>('input')
    const [lastSubmitTime, setLastSubmitTime] = useState<Date | null>(null);
    const itemsPerPage = 10

    const handleFileUpload = async (event: React.ChangeEvent<HTMLInputElement>) => {
        const file = event.target.files?.[0]
        if (file) {
            setFileName(file.name)
            try {
                const data = await file.arrayBuffer()
                const workbook = XLSX.read(data)
                const worksheet = workbook.Sheets[workbook.SheetNames[0]]
                const jsonData = XLSX.utils.sheet_to_json(worksheet)

                console.log('Parsed Excel data:', jsonData) // Debug log

                if (!jsonData || jsonData.length === 0) {
                    throw new Error('No data found in Excel file')
                }

                // Validate and format the data
                const formattedData: ParsedData[] = jsonData.map((row: any) => {
                    const phoneNumbers: string[] = []
                    const emails: string[] = []
                    const alt: string[] = []

                    // Parse phone number (single column)
                    if (row.phone_number) {
                        const phones = String(row.phone_number).split(',').map((phone: string) => phone.trim())
                        phoneNumbers.push(...phones)
                    }

                    // Parse email (single column)
                    if (row.email) {
                        const emailList = String(row.email).split(',').map((email: string) => email.trim())
                        emails.push(...emailList)
                    }

                    // Parse alt (single column)
                    if (row.alt) {
                        const altList = String(row.alt).split(',').map((altItem: string) => altItem.trim())
                        alt.push(...altList)
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
                setError(`Error parsing Excel file: ${err instanceof Error ? err.message : 'Unknown error'}. Please make sure it's a valid Excel file with the correct columns.`)
                setParsedData([])
            }
        }
    }

    const handleSubmit = async () => {
        setLastSubmitTime(new Date());
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

    const handleDownloadCSV = () => {
        alert('CSV download functionality will be implemented here.')
    }

    const totalPages = Math.ceil(parsedData.length / itemsPerPage)
    const paginatedData = parsedData.slice((currentPage - 1) * itemsPerPage, currentPage * itemsPerPage)

    return (
        <div className="bg-gray-50 min-h-screen">
            <div className="max-w-7xl mx-auto py-12 px-4 sm:px-6 lg:px-8">
                <div className="max-w-3xl mx-auto">
                    <div className="text-center mb-8">
                        <p className="mt-4 text-lg text-gray-500">
                            OpenRecon is an online platform that performs OSINT searches on your behalf for several tools such as Shodan, Sherlock, and more!
                        </p>
                    </div>

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
                                    <div className="mt-4">
                                        <p className="mt-2 text-sm text-gray-500">
                                            <FileText className="inline-block mr-1 h-4 w-4" />
                                            {fileName}
                                        </p>
                                        <p className="mt-1 text-sm text-gray-600">
                                            You have submitted "{fileName}". If this is not what you wish to submit, please refresh the page and reupload the correct file.
                                        </p>
                                    </div>
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
                            <div className="flex justify-center space-x-4 mb-4">
                                <button
                                    onClick={() => setActiveView('input')}
                                    className={`px-4 py-2 text-sm font-medium rounded-md ${
                                        activeView === 'input'
                                            ? 'bg-indigo-600 text-white'
                                            : 'bg-white text-gray-700 hover:bg-gray-50'
                                    }`}
                                >
                                    Input
                                </button>
                                <button
                                    onClick={() => setActiveView('output')}
                                    className={`px-4 py-2 text-sm font-medium rounded-md ${
                                        activeView === 'output'
                                            ? 'bg-indigo-600 text-white'
                                            : 'bg-white text-gray-700 hover:bg-gray-50'
                                    }`}
                                >
                                    Output
                                </button>
                            </div>

                            {activeView === 'input' && (
                                <>
                                    <div className="bg-white shadow sm:rounded-lg mb-8">
                                        <div className="px-4 py-5 sm:p-6">
                                            <div className="flex justify-between items-center">
                                                <h3 className="text-lg leading-6 font-medium text-gray-900">Parsed Data Preview</h3>
                                                <button
                                                    onClick={() => setShowParsedDataPreview(!showParsedDataPreview)}
                                                    className="inline-flex items-center px-3 py-1 border border-transparent text-sm font-medium rounded-md text-indigo-700 bg-indigo-100 hover:bg-indigo-200 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500"
                                                >
                                                    {showParsedDataPreview ? <ChevronUp className="h-4 w-4 mr-1" /> : <ChevronDown className="h-4 w-4 mr-1" />}
                                                    {showParsedDataPreview ? 'Hide' : 'Show'}
                                                </button>
                                            </div>
                                            {showParsedDataPreview ? (
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
                                                                        {paginatedData.map((row, i) => (
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
                                                    <div className="mt-4 flex justify-between items-center">
                                                        <button
                                                            onClick={() => setCurrentPage(prev => Math.max(prev - 1, 1))}
                                                            disabled={currentPage === 1}
                                                            className="inline-flex items-center px-4 py-2 border border-gray-300 text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50"
                                                        >
                                                            Previous
                                                        </button>
                                                        <span className="text-sm text-gray-700">
                              Page {currentPage} of {totalPages}
                            </span>
                                                        <button
                                                            onClick={() => setCurrentPage(prev => Math.min(prev + 1, totalPages))}
                                                            disabled={currentPage === totalPages}
                                                            className="inline-flex items-center px-4 py-2 border border-gray-300 text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50"
                                                        >
                                                            Next
                                                        </button>
                                                    </div>
                                                </div>
                                            ) : (
                                                <p className="mt-2 text-sm text-gray-500">Click 'Show' to view the parsed data preview.</p>
                                            )}
                                        </div>
                                    </div>

                                    <div className="bg-white shadow sm:rounded-lg">
                                        <div className="px-4 py-5 sm:p-6">
                                            <div className="flex justify-between items-center">
                                                <h3 className="text-lg leading-6 font-medium text-gray-900">JSON Preview</h3>
                                                <button
                                                    onClick={() => setShowJsonPreview(!showJsonPreview)}
                                                    className="inline-flex items-center px-3 py-1 border border-transparent text-sm font-medium rounded-md text-indigo-700 bg-indigo-100 hover:bg-indigo-200 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500"
                                                >
                                                    {showJsonPreview ? <ChevronUp className="h-4 w-4 mr-1" /> : <ChevronDown className="h-4 w-4 mr-1" />}
                                                    {showJsonPreview ? 'Hide' : 'Show'}
                                                </button>
                                            </div>
                                            <div className="mt-2 max-w-xl text-sm text-gray-500">
                                                <p>This is how the data will be sent to the backend for processing.</p>
                                            </div>
                                            {showJsonPreview && (
                                                <div className="mt-5">
                          <pre className="bg-gray-200 p-4 rounded-md overflow-x-auto text-xs h-60 overflow-y-auto text-black">
                            {JSON.stringify(parsedData, null, 2)}
                          </pre>
                                                </div>
                                            )}
                                        </div>
                                    </div>
                                </>
                            )}

                            {activeView === 'output' && (
                                <div className="bg-white shadow sm:rounded-lg mb-8">
                                    <div className="px-4 py-5 sm:p-6">
                                        <h3 className="text-lg leading-6 font-medium text-gray-900">Data Summary</h3>
                                        <div className="mt-5 grid grid-cols-1 gap-5 sm:grid-cols-2">
                                            <div className="bg-white overflow-hidden shadow rounded-lg">
                                                <div className="px-4 py-5 sm:p-6">
                                                    <dt className="text-sm font-medium text-gray-500 truncate">Number of Users</dt>
                                                    <dd className="mt-1 text-3xl font-semibold text-gray-900">{parsedData.length}</dd>
                                                </div>
                                            </div>
                                            <div className="bg-white overflow-hidden shadow rounded-lg">
                                                <div className="px-4 py-5 sm:p-6">
                                                    <dt className="text-sm font-medium text-gray-500 truncate">Number of Exposed Surfaces</dt>
                                                    <dd className="mt-1 text-3xl font-semibold text-gray-900">
                                                        {parsedData.reduce((sum, user) => sum + user.phoneNumbers.length + user.emails.length + user.alt.length, 0)}
                                                    </dd>
                                                </div>
                                            </div>
                                        </div>
                                        <div className="mt-5">
                                            <h4 className="text-md font-medium text-gray-900 mb-2">List of Compromised Users</h4>
                                            <div className="bg-gray-100 rounded-md p-4 h-40 overflow-y-auto">
                                                <ul className="list-disc list-inside">
                                                    {parsedData.map((user, index) => (
                                                        <li key={index} className="text-sm text-gray-600">{user.fname} {user.lname}</li>
                                                    ))}
                                                </ul>
                                            </div>
                                        </div>
                                        <div className="mt-5 flex flex-col items-center">
                                            <button
                                                onClick={handleDownloadCSV}
                                                className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500"
                                            >
                                                <Download className="mr-2 h-4 w-4" />
                                                Download CSV
                                            </button>
                                            {lastSubmitTime && (
                                                <p className="mt-2 text-sm text-gray-500">
                                                    Generated at: {lastSubmitTime.toLocaleString()}
                                                </p>
                                            )}
                                        </div>
                                    </div>
                                </div>
                            )}

                            {activeView === 'input' && (
                                <div className="mt-8 flex justify-center">
                                    <button
                                        onClick={handleSubmit}
                                        className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500"
                                    >
                                        <Send className="mr-2 h-4 w-4" />
                                        Submit Data
                                    </button>
                                </div>
                            )}
                        </div>
                    )}

                    {parsedData.length === 0 && (
                        <div className="mt-8">
                            <div className="bg-white shadow sm:rounded-lg mb-8">
                                <div className="px-4 py-5 sm:p-6">
                                    <h3 className="text-lg leading-6 font-medium text-gray-900">Parsed Data Preview</h3>
                                    <p className="mt-2 text-sm text-gray-500">
                                        Upload an Excel file to see a preview of the parsed data here. This section will show the first 10 rows of your data after processing.
                                    </p>
                                </div>
                            </div>

                            <div className="bg-white shadow sm:rounded-lg">
                                <div className="px-4 py-5 sm:p-6">
                                    <h3 className="text-lg leading-6 font-medium text-gray-900">JSON Preview</h3>
                                    <p className="mt-2 text-sm text-gray-500">
                                        After uploading and processing your Excel file, you'll see a JSON representation of your data here. This is the format that will be sent to the backend for further processing.
                                    </p>
                                </div>
                            </div>
                        </div>
                    )}
                </div>
            </div>
        </div>
    )
}

