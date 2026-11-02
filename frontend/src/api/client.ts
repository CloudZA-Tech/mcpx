import axios from 'axios'

const api = axios.create({
    baseURL: import.meta.env.VITE_API_URL || '/api',
    headers: {
        'Content-Type': 'application/json',
    },
})

api.interceptors.request.use((config) => {
    const token = localStorage.getItem('token')
    if (token) {
        config.headers.Authorization = `Bearer ${token}`
    }
    return config
})

api.interceptors.response.use(
    (response) => response,
    (error) => {
        if (error.response?.status === 401) {
            localStorage.removeItem('token')
            window.location.href = '/login'
        }
        return Promise.reject(error)
    }
)

/**
 * Extract the backend's error message (sent as plain text) from a failed request,
 * instead of axios' generic "Request failed with status code ..."
 */
export function apiErrorMessage(e: unknown, fallback: string): string {
    if (axios.isAxiosError(e)) {
        const data = e.response?.data
        if (typeof data === 'string' && data.trim()) return data
        if (data && typeof data === 'object' && 'message' in data) return String(data.message)
        return e.message
    }
    return e instanceof Error ? e.message : fallback
}

export default api
