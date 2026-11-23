import { describe, it, expect, vi, beforeEach } from 'vitest'
import { shallowMount, flushPromises } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { ref } from 'vue'

vi.mock('vue-router', () => ({
    useRouter: () => ({ push: vi.fn(), replace: vi.fn() }),
    useRoute: () => ({ params: { name: 'reports' }, query: {} }),
    RouterLink: { template: '<a><slot /></a>' }
}))

const state = vi.hoisted(() => ({
    server: {
        name: 'reports',
        url: 'http://localhost:3000/mcp',
        status: 'healthy',
        transport: 'streamable-http',
        enabled: true,
        auth_type: 'bearer',
        forward_identity: false,
        created_at: '2026-11-23T00:00:00Z',
        updated_at: '2026-11-23T00:00:00Z',
    },
    canWrite: true,
}))

vi.mock('@/stores/servers', () => ({
    useServersStore: vi.fn(() => ({
        getServerByName: vi.fn(() => ({ ...state.server })),
        fetchServers: vi.fn().mockResolvedValue([]),
        testServer: vi.fn().mockResolvedValue({ success: true, message: 'ok', latency_ms: 1, status_code: 200, tools: [] }),
    }))
}))

vi.mock('@/composables/usePermissions', () => ({
    usePermissions: () => ({ canWrite: ref(state.canWrite) })
}))

const api = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn(), put: vi.fn(), delete: vi.fn() }))
vi.mock('@/api/client', () => ({ default: api }))

import ServerDetails from '@/views/dashboard/ServerDetails.vue'

const mountPage = async () => {
    const wrapper = shallowMount(ServerDetails, {
        global: { stubs: { DashboardLayout: { template: '<div><slot /></div>' }, ToolGovernance: true } }
    })
    await flushPromises()
    return wrapper
}

describe('ServerDetails.vue caller identity', () => {
    beforeEach(() => {
        setActivePinia(createPinia())
        vi.clearAllMocks()
        state.server.forward_identity = false
        state.canWrite = true
        vi.stubGlobal('confirm', vi.fn(() => true))
    })

    it('turns identity forwarding on and shows the new secret once', async () => {
        api.put.mockImplementation(async () => {
            state.server.forward_identity = true
            return { data: { forward_identity: true, identity_secret: 'secret-shown-once' } }
        })
        const wrapper = await mountPage()

        await wrapper.get('[data-test="identity-toggle"]').trigger('click')
        await flushPromises()

        expect(api.put).toHaveBeenCalledWith('/servers/reports/identity', { enabled: true })
        expect(wrapper.get('[data-test="identity-secret"]').text()).toContain('secret-shown-once')
        expect(wrapper.find('[data-test="identity-rotate"]').exists()).toBe(true)
    })

    it('asks before rotating and calls the rotate endpoint', async () => {
        state.server.forward_identity = true
        api.post.mockImplementation(async (url: string) =>
            url.endsWith('/identity/rotate')
                ? { data: { forward_identity: true, identity_secret: 'rotated-secret' } }
                : { data: {} })
        const wrapper = await mountPage()

        await wrapper.get('[data-test="identity-rotate"]').trigger('click')
        await flushPromises()

        expect(window.confirm).toHaveBeenCalled()
        expect(api.post).toHaveBeenCalledWith('/servers/reports/identity/rotate')
        expect(wrapper.get('[data-test="identity-secret"]').text()).toContain('rotated-secret')
    })

    it('does nothing when turning off is not confirmed', async () => {
        state.server.forward_identity = true
        vi.stubGlobal('confirm', vi.fn(() => false))
        const wrapper = await mountPage()

        await wrapper.get('[data-test="identity-toggle"]').trigger('click')
        await flushPromises()

        expect(api.put).not.toHaveBeenCalled()
    })

    it('hides the controls from members', async () => {
        state.canWrite = false
        const wrapper = await mountPage()
        expect(wrapper.find('[data-test="identity-card"]').exists()).toBe(false)
        expect(wrapper.text()).toContain('Caller identity:')
    })
})
