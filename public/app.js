// DOM Elements
const promptInput = document.getElementById('promptInput');
const sendPromptBtn = document.getElementById('sendPrompt');
const responseDiv = document.getElementById('response');
const historyDiv = document.getElementById('history');
const clearHistoryBtn = document.getElementById('clearHistory');
const charCount = document.getElementById('charCount');
const securityScore = document.getElementById('securityScore');
const securityChecks = document.getElementById('securityChecks');
const copyResponseBtn = document.getElementById('copyResponseBtn');
const exportHistoryBtn = document.getElementById('exportHistoryBtn');
const templateBtn = document.getElementById('templateBtn');
const clearPromptBtn = document.getElementById('clearPromptBtn');
const settingsBtn = document.getElementById('settingsBtn');
const helpBtn = document.getElementById('helpBtn');
const settingsModal = document.getElementById('settingsModal');
const helpModal = document.getElementById('helpModal');
const closeSettingsBtn = document.getElementById('closeSettingsBtn');
const closeHelpBtn = document.getElementById('closeHelpBtn');
const autoValidateCheck = document.getElementById('autoValidate');
const darkModeCheck = document.getElementById('darkMode');
const securityLevelSelect = document.getElementById('securityLevel');

// Statistics Elements
const totalPromptsEl = document.getElementById('totalPrompts');
const totalIssuesEl = document.getElementById('totalIssues');
const successRateEl = document.getElementById('successRate');
const avgResponseTimeEl = document.getElementById('avgResponseTime');

// State
let promptHistory = [];
let stats = {
    totalPrompts: 0,
    totalIssues: 0,
    successCount: 0,
    totalResponseTime: 0
};

// Settings
let settings = {
    autoValidate: true,
    darkMode: false,
    securityLevel: 'standard'
};

// Load settings from localStorage
function loadSettings() {
    const savedSettings = localStorage.getItem('promptLabSettings');
    if (savedSettings) {
        settings = { ...settings, ...JSON.parse(savedSettings) };
        applySettings();
    }
}

// Save settings to localStorage
function saveSettings() {
    localStorage.setItem('promptLabSettings', JSON.stringify(settings));
}

// Apply settings to UI
function applySettings() {
    // Dark mode
    document.documentElement.setAttribute('data-theme', settings.darkMode ? 'dark' : 'light');
    darkModeCheck.checked = settings.darkMode;
    
    // Auto validate
    autoValidateCheck.checked = settings.autoValidate;
    
    // Security level
    securityLevelSelect.value = settings.securityLevel;
}

// Update statistics
function updateStats() {
    stats.successRate = (stats.successCount / stats.totalPrompts * 100) || 0;
    const avgResponseTime = stats.totalPrompts ? stats.totalResponseTime / stats.totalPrompts : 0;
    
    totalPromptsEl.textContent = stats.totalPrompts;
    totalIssuesEl.textContent = stats.totalIssues;
    successRateEl.textContent = `${stats.successRate.toFixed(1)}%`;
    avgResponseTimeEl.textContent = `${avgResponseTime.toFixed(0)}ms`;
}

// API Functions
async function sendPrompt(prompt) {
    const startTime = Date.now();
    try {
        const response = await fetch('/api/test-prompt', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ 
                prompt,
                securityLevel: settings.securityLevel
            })
        });
        
        if (!response.ok) {
            throw new Error('Request failed');
        }
        
        const data = await response.json();
        
        // Update statistics
        stats.totalPrompts++;
        stats.totalResponseTime += Date.now() - startTime;
        if (data.securityScore >= 0.7) stats.successCount++;
        if (data.risks?.length) stats.totalIssues += data.risks.length;
        
        updateStats();
        return data;
    } catch (error) {
        console.error('Error:', error);
        return null;
    }
}

async function getHistory() {
    try {
        const response = await fetch('/api/attempts');
        const data = await response.json();
        promptHistory = data;
        return data;
    } catch (error) {
        console.error('Error:', error);
        return [];
    }
}

async function clearHistory() {
    try {
        await fetch('/api/clear-attempts', { method: 'POST' });
        promptHistory = [];
        stats = {
            totalPrompts: 0,
            totalIssues: 0,
            successCount: 0,
            totalResponseTime: 0
        };
        updateStats();
        updateHistory();
    } catch (error) {
        console.error('Error:', error);
    }
}

// UI Functions
function updateResponse(data) {
    // Update security score
    if (data.securityScore !== undefined) {
        const scoreClass = data.securityScore >= 0.7 ? 'high' : 
                         data.securityScore >= 0.4 ? 'medium' : 'low';
        securityScore.textContent = `${(data.securityScore * 100).toFixed(0)}%`;
        securityScore.className = `security-score ${scoreClass}`;
    }
    
    // Update security checks
    securityChecks.innerHTML = '';
    if (data.risks) {
        data.risks.forEach(risk => {
            const checkEl = document.createElement('div');
            checkEl.className = `security-check ${risk.level.toLowerCase()}`;
            checkEl.innerHTML = `
                <i class="fas fa-${risk.level === 'PASS' ? 'check' : 
                                  risk.level === 'WARN' ? 'exclamation-triangle' : 
                                  'times-circle'} mr-2"></i>
                <span>${risk.message}</span>
            `;
            securityChecks.appendChild(checkEl);
        });
    }
    
    // Update response
    responseDiv.textContent = data.response || 'No response received';
}

function createHistoryItem(attempt) {
    const item = document.createElement('div');
    item.className = 'history-item bg-white rounded-lg shadow-sm p-4 border border-gray-100';
    
    const timestamp = new Date(attempt.timestamp).toLocaleString();
    const scoreClass = attempt.securityScore >= 0.7 ? 'high' : 
                      attempt.securityScore >= 0.4 ? 'medium' : 'low';
    
    item.innerHTML = `
        <div class="flex justify-between items-start mb-2">
            <span class="text-sm text-gray-500">${timestamp}</span>
            <span class="security-score ${scoreClass}">
                ${(attempt.securityScore * 100).toFixed(0)}%
            </span>
        </div>
        <div class="mb-2">
            <strong>Prompt:</strong>
            <pre class="mt-1 text-sm bg-gray-50 p-2 rounded">${attempt.prompt}</pre>
        </div>
        <div>
            <strong>Response:</strong>
            <pre class="mt-1 text-sm bg-gray-50 p-2 rounded">${attempt.response}</pre>
        </div>
    `;
    
    return item;
}

async function updateHistory() {
    const attempts = await getHistory();
    historyDiv.innerHTML = '';
    
    attempts.reverse().forEach(attempt => {
        historyDiv.appendChild(createHistoryItem(attempt));
    });
}

function exportHistory() {
    const data = JSON.stringify(promptHistory, null, 2);
    const blob = new Blob([data], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `prompt-history-${new Date().toISOString()}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

// Event Listeners
promptInput.addEventListener('input', () => {
    const length = promptInput.value.length;
    charCount.textContent = length;
    charCount.className = `char-count ${length > 500 ? 'danger' : 
                                      length > 300 ? 'warning' : ''}`;
});

sendPromptBtn.addEventListener('click', async () => {
    const prompt = promptInput.value.trim();
    if (!prompt) return;
    
    sendPromptBtn.disabled = true;
    sendPromptBtn.innerHTML = '<i class="fas fa-spinner fa-spin mr-2"></i>Analyzing...';
    
    const result = await sendPrompt(prompt);
    
    if (result) {
        updateResponse(result);
        await updateHistory();
    } else {
        updateResponse({ 
            response: 'Error: Failed to send prompt',
            securityScore: 0,
            risks: [{ level: 'FAIL', message: 'Failed to process prompt' }]
        });
    }
    
    sendPromptBtn.disabled = false;
    sendPromptBtn.innerHTML = '<i class="fas fa-paper-plane mr-2"></i>Send Prompt';
});

clearHistoryBtn.addEventListener('click', clearHistory);
exportHistoryBtn.addEventListener('click', exportHistory);
clearPromptBtn.addEventListener('click', () => {
    promptInput.value = '';
    charCount.textContent = '0';
    charCount.className = 'char-count';
});

copyResponseBtn.addEventListener('click', () => {
    navigator.clipboard.writeText(responseDiv.textContent);
    copyResponseBtn.innerHTML = '<i class="fas fa-check"></i>';
    setTimeout(() => {
        copyResponseBtn.innerHTML = '<i class="fas fa-copy"></i>';
    }, 2000);
});

// Modal handlers
settingsBtn.addEventListener('click', () => {
    settingsModal.classList.remove('hidden');
    settingsModal.classList.add('flex');
});

helpBtn.addEventListener('click', () => {
    helpModal.classList.remove('hidden');
    helpModal.classList.add('flex');
});

closeSettingsBtn.addEventListener('click', () => {
    settingsModal.classList.add('hidden');
    settingsModal.classList.remove('flex');
});

closeHelpBtn.addEventListener('click', () => {
    helpModal.classList.add('hidden');
    helpModal.classList.remove('flex');
});

// Settings handlers
darkModeCheck.addEventListener('change', () => {
    settings.darkMode = darkModeCheck.checked;
    saveSettings();
    applySettings();
});

autoValidateCheck.addEventListener('change', () => {
    settings.autoValidate = autoValidateCheck.checked;
    saveSettings();
});

securityLevelSelect.addEventListener('change', () => {
    settings.securityLevel = securityLevelSelect.value;
    saveSettings();
});

// Initial load
loadSettings();
updateHistory(); 