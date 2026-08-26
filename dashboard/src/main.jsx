import { StrictMode, useState, useEffect } from 'react'
import { createRoot } from 'react-dom/client'
import App from './App'
import './index.css'
import './App.css'

function AppWrapper() {
  const [runtimeError, setRuntimeError] = useState(null)

  useEffect(() => {
    const handleGlobalError = (event) => {
      console.error('[Global Error Caught]:', event.error || event.message)
      setRuntimeError(event.error?.message || event.message || 'An unexpected runtime error occurred.')
    }

    const handlePromiseRejection = (event) => {
      console.error('[Unhandled Promise Rejection]:', event.reason)
      const message = event.reason?.message || String(event.reason || 'Network or API request failed.')
      setRuntimeError(message)
    }

    window.addEventListener('error', handleGlobalError)
    window.addEventListener('unhandledrejection', handlePromiseRejection)

    return () => {
      window.removeEventListener('error', handleGlobalError)
      window.removeEventListener('unhandledrejection', handlePromiseRejection)
    }
  }, [])

  if (runtimeError) {
    return (
      <div className="min-h-screen bg-slate-900 text-slate-100 flex items-center justify-center p-6 font-sans">
        <div className="max-w-md w-full bg-slate-800 border border-slate-700 rounded-xl p-6 text-center shadow-2xl">
          <div className="text-4xl mb-3">⚠️</div>
          <h2 className="text-xl font-bold text-red-400 mb-2">Application Exception</h2>
          <p className="text-slate-400 text-sm mb-6 leading-relaxed">
            {runtimeError}
          </p>
          <div className="flex gap-3 justify-center">
            <button
              type="button"
              onClick={() => setRuntimeError(null)}
              className="bg-slate-700 hover:bg-slate-600 text-slate-200 font-semibold px-4 py-2 rounded-lg text-sm transition-colors cursor-pointer"
            >
              Dismiss
            </button>
            <button
              type="button"
              onClick={() => window.location.reload()}
              className="bg-blue-600 hover:bg-blue-500 text-white font-semibold px-4 py-2 rounded-lg text-sm transition-colors cursor-pointer"
            >
              Reload Page
            </button>
          </div>
        </div>
      </div>
    )
  }

  return <App />
}

const container = document.getElementById('root')

if (!container) {
  throw new Error('Root container missing in index.html. Ensure <div id="root"></div> is present.')
}

const root = createRoot(container)

root.render(
  <StrictMode>
    <AppWrapper />
  </StrictMode>
)