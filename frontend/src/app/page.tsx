import OpenReconUploader from './components/OpenReconUploader'

export default function Home() {
  return (
      <div className="min-h-screen bg-gray-100">
        <header className="bg-white shadow">
          <div className="max-w-7xl mx-auto py-6 px-4 sm:px-6 lg:px-8">
            <h1 className="text-3xl font-bold text-gray-900">OpenRecon Data Upload</h1>
          </div>
        </header>
        <main>
          <OpenReconUploader />
        </main>
      </div>
  )
}

