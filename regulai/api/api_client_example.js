/**
 * RegulAI API Client Example
 * Cliente JavaScript/TypeScript para integrar con la API de RegulAI
 */

class RegulAIClient {
    constructor(baseURL = 'http://localhost:8000/api') {
        this.baseURL = baseURL;
        this.token = null;
    }

    /**
     * Set authentication token
     */
    setToken(token) {
        this.token = token;
        // Save to localStorage for persistence
        if (typeof window !== 'undefined') {
            localStorage.setItem('regulai_token', token);
        }
    }

    /**
     * Get authentication token
     */
    getToken() {
        if (!this.token && typeof window !== 'undefined') {
            this.token = localStorage.getItem('regulai_token');
        }
        return this.token;
    }

    /**
     * Make HTTP request
     */
    async request(endpoint, options = {}) {
        const url = `${this.baseURL}${endpoint}`;
        const headers = {
            'Content-Type': 'application/json',
            ...options.headers,
        };

        const token = this.getToken();
        if (token) {
            headers['Authorization'] = `Token ${token}`;
        }

        const config = {
            ...options,
            headers,
        };

        if (options.body && typeof options.body === 'object') {
            config.body = JSON.stringify(options.body);
        }

        try {
            const response = await fetch(url, config);
            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.error || `HTTP error! status: ${response.status}`);
            }

            return data;
        } catch (error) {
            console.error('API request failed:', error);
            throw error;
        }
    }

    // ==================== Authentication ====================

    /**
     * Login user and get token
     */
    async login(username, password) {
        const data = await this.request('/auth/login/', {
            method: 'POST',
            body: { username, password },
        });

        if (data.token) {
            this.setToken(data.token);
        }

        return data;
    }

    /**
     * Logout user
     */
    async logout() {
        const data = await this.request('/auth/logout/', {
            method: 'POST',
        });

        this.token = null;
        if (typeof window !== 'undefined') {
            localStorage.removeItem('regulai_token');
        }

        return data;
    }

    /**
     * Get current user information
     */
    async getCurrentUser() {
        return await this.request('/auth/me/');
    }

    // ==================== Chat ====================

    /**
     * Send chat message
     */
    async sendMessage(content, conversationId = null, engineId = null, modelId = null) {
        return await this.request('/chat/send/', {
            method: 'POST',
            body: {
                content,
                conversation_id: conversationId,
                engine_id: engineId,
                model_id: modelId,
            },
        });
    }

    // ==================== Conversations ====================

    /**
     * List conversations
     */
    async getConversations(page = 1, pageSize = 20) {
        return await this.request(`/conversations/?page=${page}&page_size=${pageSize}`);
    }

    /**
     * Get conversation details
     */
    async getConversation(conversationId) {
        return await this.request(`/conversations/${conversationId}/`);
    }

    /**
     * Get conversation messages
     */
    async getConversationMessages(conversationId) {
        return await this.request(`/conversations/${conversationId}/messages/`);
    }

    /**
     * Create new conversation
     */
    async createConversation(title = '') {
        return await this.request('/conversations/', {
            method: 'POST',
            body: { title },
        });
    }

    /**
     * Delete conversation
     */
    async deleteConversation(conversationId) {
        return await this.request(`/conversations/${conversationId}/`, {
            method: 'DELETE',
        });
    }

    // ==================== Engines ====================

    /**
     * Get available AI engines
     */
    async getEngines(page = 1, pageSize = 20) {
        return await this.request(`/company-engines/?page=${page}&page_size=${pageSize}`);
    }

    /**
     * Get engine models
     */
    async getEngineModels(engineId) {
        return await this.request(`/company-engines/${engineId}/models/`);
    }

    // ==================== Alerts ====================

    /**
     * Get all alerts
     */
    async getAlerts(page = 1, pageSize = 20) {
        return await this.request(`/alerts/?page=${page}&page_size=${pageSize}`);
    }

    /**
     * Get unresolved alerts
     */
    async getUnresolvedAlerts() {
        return await this.request('/alerts/unresolved/');
    }

    /**
     * Resolve alert
     */
    async resolveAlert(alertId) {
        return await this.request(`/alerts/${alertId}/resolve/`, {
            method: 'POST',
        });
    }

    // ==================== Rules ====================

    /**
     * Get rules groups
     */
    async getRulesGroups(page = 1, pageSize = 20) {
        return await this.request(`/rules-groups/?page=${page}&page_size=${pageSize}`);
    }

    /**
     * Get rules
     */
    async getRules(page = 1, pageSize = 20) {
        return await this.request(`/rules/?page=${page}&page_size=${pageSize}`);
    }

    // ==================== Dashboard ====================

    /**
     * Get dashboard statistics
     */
    async getDashboardStats() {
        return await this.request('/dashboard/stats/');
    }

    // ==================== Admin ====================

    /**
     * Get departments
     */
    async getDepartments(page = 1, pageSize = 20) {
        return await this.request(`/departments/?page=${page}&page_size=${pageSize}`);
    }

    /**
     * Get roles
     */
    async getRoles(page = 1, pageSize = 20) {
        return await this.request(`/roles/?page=${page}&page_size=${pageSize}`);
    }

    /**
     * Get profiles
     */
    async getProfiles(page = 1, pageSize = 20) {
        return await this.request(`/profiles/?page=${page}&page_size=${pageSize}`);
    }
}

// ==================== Usage Examples ====================

/**
 * Example 1: Login and send a message
 */
async function example1() {
    const client = new RegulAIClient();

    try {
        // Login
        const loginResponse = await client.login('admin', 'admin');
        console.log('Logged in:', loginResponse);

        // Send a message
        const chatResponse = await client.sendMessage('Hola, ¿cómo estás?');
        console.log('Chat response:', chatResponse);

        // Get conversation messages
        const messages = await client.getConversationMessages(chatResponse.conversation_id);
        console.log('Messages:', messages);
    } catch (error) {
        console.error('Error:', error);
    }
}

/**
 * Example 2: Continue an existing conversation
 */
async function example2() {
    const client = new RegulAIClient();

    try {
        // Assuming already logged in
        const conversationId = 1;

        // Send follow-up message
        const response = await client.sendMessage(
            '¿Me puedes dar más información?',
            conversationId
        );
        console.log('Response:', response);
    } catch (error) {
        console.error('Error:', error);
    }
}

/**
 * Example 3: Get dashboard statistics
 */
async function example3() {
    const client = new RegulAIClient();

    try {
        const stats = await client.getDashboardStats();
        console.log('Dashboard stats:', stats);
    } catch (error) {
        console.error('Error:', error);
    }
}

/**
 * Example 4: React Hook for chat
 */
function useChatExample() {
    // This is pseudocode for a React hook
    const [messages, setMessages] = React.useState([]);
    const [conversationId, setConversationId] = React.useState(null);
    const client = new RegulAIClient();

    const sendMessage = async (content) => {
        try {
            const response = await client.sendMessage(content, conversationId);

            if (!conversationId) {
                setConversationId(response.conversation_id);
            }

            // Add user message
            if (response.user_message) {
                setMessages(prev => [...prev, response.user_message]);
            }

            // Add assistant message
            if (response.assistant_message) {
                setMessages(prev => [...prev, response.assistant_message]);
            }

            return response;
        } catch (error) {
            console.error('Error sending message:', error);
            throw error;
        }
    };

    return { messages, sendMessage, conversationId };
}

// Export for module usage
if (typeof module !== 'undefined' && module.exports) {
    module.exports = RegulAIClient;
}
