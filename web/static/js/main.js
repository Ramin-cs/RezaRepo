// ARAT Web Panel - Main JavaScript

// Global variables
let socket;
let currentTaskId = null;

// Initialize when document is ready
document.addEventListener('DOMContentLoaded', function() {
    initializeSocketIO();
    initializeEventListeners();
    loadDashboardData();
});

// Socket.IO initialization
function initializeSocketIO() {
    socket = io();
    
    socket.on('connect', function() {
        console.log('Connected to server');
        showToast('متصل شدید', 'success');
    });
    
    socket.on('disconnect', function() {
        console.log('Disconnected from server');
        showToast('اتصال قطع شد', 'warning');
    });
    
    socket.on('task_update', function(data) {
        handleTaskUpdate(data);
    });
    
    socket.on('phase_completed', function(data) {
        handlePhaseCompleted(data);
    });
    
    socket.on('phase_error', function(data) {
        handlePhaseError(data);
    });
    
    socket.on('task_completed', function(data) {
        handleTaskCompleted(data);
    });
    
    socket.on('task_error', function(data) {
        handleTaskError(data);
    });
}

// Initialize event listeners
function initializeEventListeners() {
    // Toast close buttons
    document.querySelectorAll('.btn-close').forEach(button => {
        button.addEventListener('click', function() {
            const toast = this.closest('.toast');
            if (toast) {
                const bsToast = bootstrap.Toast.getInstance(toast);
                if (bsToast) {
                    bsToast.hide();
                }
            }
        });
    });
    
    // Form submissions
    document.querySelectorAll('form').forEach(form => {
        form.addEventListener('submit', function(e) {
            e.preventDefault();
            handleFormSubmit(this);
        });
    });
}

// Show toast notification
function showToast(message, type = 'info') {
    const toastContainer = document.querySelector('.toast-container');
    const toast = document.getElementById('toast');
    const toastBody = document.getElementById('toast-body');
    
    if (toast && toastBody) {
        // Update toast content
        toastBody.textContent = message;
        
        // Update toast header icon based on type
        const headerIcon = toast.querySelector('.fas');
        if (headerIcon) {
            headerIcon.className = `fas ${getToastIcon(type)} me-2`;
        }
        
        // Show toast
        const bsToast = new bootstrap.Toast(toast);
        bsToast.show();
    }
}

// Get toast icon based on type
function getToastIcon(type) {
    switch (type) {
        case 'success':
            return 'fa-check-circle text-success';
        case 'error':
        case 'danger':
            return 'fa-exclamation-circle text-danger';
        case 'warning':
            return 'fa-exclamation-triangle text-warning';
        case 'info':
        default:
            return 'fa-info-circle text-primary';
    }
}

// Show loading modal
function showLoadingModal(title = 'در حال پردازش...', message = 'لطفاً صبر کنید') {
    const modal = document.getElementById('loadingModal');
    const titleElement = document.getElementById('loading-title');
    const messageElement = document.getElementById('loading-message');
    
    if (modal && titleElement && messageElement) {
        titleElement.textContent = title;
        messageElement.textContent = message;
        
        const bsModal = new bootstrap.Modal(modal);
        bsModal.show();
    }
}

// Hide loading modal
function hideLoadingModal() {
    const modal = document.getElementById('loadingModal');
    if (modal) {
        const bsModal = bootstrap.Modal.getInstance(modal);
        if (bsModal) {
            bsModal.hide();
        }
    }
}

// Handle form submission
function handleFormSubmit(form) {
    const formData = new FormData(form);
    const data = Object.fromEntries(formData.entries());
    
    // Add CSRF token if available
    const csrfToken = document.querySelector('meta[name="csrf-token"]');
    if (csrfToken) {
        data.csrf_token = csrfToken.getAttribute('content');
    }
    
    // Submit form data
    submitForm(form.action || window.location.href, data, form.method || 'POST')
        .then(response => {
            if (response.success) {
                showToast(response.message || 'عملیات با موفقیت انجام شد', 'success');
                
                // Close modal if form is in modal
                const modal = form.closest('.modal');
                if (modal) {
                    const bsModal = bootstrap.Modal.getInstance(modal);
                    if (bsModal) {
                        bsModal.hide();
                    }
                }
                
                // Refresh page or update content
                if (response.refresh) {
                    setTimeout(() => {
                        window.location.reload();
                    }, 1000);
                }
            } else {
                showToast(response.error || 'خطا در انجام عملیات', 'error');
            }
        })
        .catch(error => {
            console.error('Form submission error:', error);
            showToast('خطا در ارسال فرم', 'error');
        });
}

// Submit form data
async function submitForm(url, data, method = 'POST') {
    try {
        const response = await fetch(url, {
            method: method,
            headers: {
                'Content-Type': 'application/json',
                'X-Requested-With': 'XMLHttpRequest'
            },
            body: JSON.stringify(data)
        });
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        return await response.json();
    } catch (error) {
        console.error('Submit error:', error);
        throw error;
    }
}

// Make API request
async function apiRequest(endpoint, method = 'GET', data = null) {
    try {
        const options = {
            method: method,
            headers: {
                'Content-Type': 'application/json',
                'X-Requested-With': 'XMLHttpRequest'
            }
        };
        
        if (data) {
            options.body = JSON.stringify(data);
        }
        
        const response = await fetch(`/api${endpoint}`, options);
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        return await response.json();
    } catch (error) {
        console.error('API request error:', error);
        throw error;
    }
}

// Load dashboard data
function loadDashboardData() {
    // Load targets count
    apiRequest('/targets')
        .then(response => {
            if (response.success) {
                document.getElementById('total-targets').textContent = response.targets.length;
            }
        })
        .catch(error => {
            console.error('Error loading targets:', error);
        });
    
    // Load system status
    loadSystemStatus();
    
    // Load recent activity
    loadRecentActivity();
    
    // Load API keys status
    loadApiKeysStatus();
}

// Load system status
function loadSystemStatus() {
    // Simulate system status (in real implementation, this would come from API)
    const apiStatus = document.getElementById('api-status');
    const dbStatus = document.getElementById('db-status');
    const memoryUsage = document.getElementById('memory-usage');
    const cpuUsage = document.getElementById('cpu-usage');
    
    if (apiStatus) {
        apiStatus.textContent = 'آنلاین';
        apiStatus.className = 'badge bg-success';
    }
    
    if (dbStatus) {
        dbStatus.textContent = 'متصل';
        dbStatus.className = 'badge bg-success';
    }
    
    if (memoryUsage) {
        memoryUsage.textContent = '45%';
    }
    
    if (cpuUsage) {
        cpuUsage.textContent = '23%';
    }
}

// Load recent activity
function loadRecentActivity() {
    const container = document.getElementById('recent-activity');
    if (!container) return;
    
    // Simulate recent activity (in real implementation, this would come from API)
    const activities = [
        {
            time: '2 دقیقه پیش',
            action: 'اسکن example.com تکمیل شد',
            type: 'success'
        },
        {
            time: '5 دقیقه پیش',
            action: 'هدف جدید test.com اضافه شد',
            type: 'info'
        },
        {
            time: '10 دقیقه پیش',
            action: 'فاز 1 برای demo.com شروع شد',
            type: 'warning'
        }
    ];
    
    container.innerHTML = activities.map(activity => `
        <div class="d-flex align-items-center mb-3">
            <div class="flex-shrink-0">
                <i class="fas fa-circle text-${activity.type}"></i>
            </div>
            <div class="flex-grow-1 ms-3">
                <div class="fw-bold">${activity.action}</div>
                <small class="text-muted">${activity.time}</small>
            </div>
        </div>
    `).join('');
}

// Load API keys status
function loadApiKeysStatus() {
    const container = document.getElementById('api-keys-status');
    if (!container) return;
    
    // Simulate API keys status (in real implementation, this would come from API)
    const apiKeys = [
        { name: 'Shodan', status: 'configured' },
        { name: 'VirusTotal', status: 'configured' },
        { name: 'Censys', status: 'not_configured' },
        { name: 'SecurityTrails', status: 'configured' }
    ];
    
    container.innerHTML = apiKeys.map(key => `
        <div class="d-flex justify-content-between align-items-center mb-2">
            <span>${key.name}:</span>
            <span class="badge ${key.status === 'configured' ? 'bg-success' : 'bg-secondary'}">
                ${key.status === 'configured' ? 'تنظیم شده' : 'تنظیم نشده'}
            </span>
        </div>
    `).join('');
}

// Handle task update
function handleTaskUpdate(data) {
    console.log('Task update:', data);
    
    // Update progress bar
    const progressBar = document.getElementById('progress-bar');
    if (progressBar) {
        progressBar.style.width = `${data.progress}%`;
        progressBar.setAttribute('aria-valuenow', data.progress);
    }
    
    // Update current status
    const currentStatus = document.getElementById('current-status');
    if (currentStatus) {
        currentStatus.textContent = data.message;
    }
    
    // Update phase info
    const progressPhase = document.getElementById('progress-phase');
    if (progressPhase) {
        progressPhase.textContent = `فاز: ${data.current_phase}`;
    }
}

// Handle phase completed
function handlePhaseCompleted(data) {
    console.log('Phase completed:', data);
    
    // Add result to results container
    const resultsContainer = document.getElementById('results-container');
    if (resultsContainer) {
        const resultDiv = document.createElement('div');
        resultDiv.className = 'alert alert-success';
        resultDiv.innerHTML = `
            <i class="fas fa-check-circle me-2"></i>
            <strong>فاز ${data.phase}:</strong> ${data.message}
        `;
        resultsContainer.appendChild(resultDiv);
        resultsContainer.scrollTop = resultsContainer.scrollHeight;
    }
    
    showToast(`فاز ${data.phase} تکمیل شد`, 'success');
}

// Handle phase error
function handlePhaseError(data) {
    console.log('Phase error:', data);
    
    // Add error to results container
    const resultsContainer = document.getElementById('results-container');
    if (resultsContainer) {
        const errorDiv = document.createElement('div');
        errorDiv.className = 'alert alert-danger';
        errorDiv.innerHTML = `
            <i class="fas fa-exclamation-circle me-2"></i>
            <strong>فاز ${data.phase}:</strong> ${data.message}
        `;
        resultsContainer.appendChild(errorDiv);
        resultsContainer.scrollTop = resultsContainer.scrollHeight;
    }
    
    showToast(`خطا در فاز ${data.phase}`, 'error');
}

// Handle task completed
function handleTaskCompleted(data) {
    console.log('Task completed:', data);
    
    hideLoadingModal();
    showToast('Reconnaissance تکمیل شد', 'success');
    
    // Redirect to results page or show results
    setTimeout(() => {
        window.location.href = '/reports';
    }, 2000);
}

// Handle task error
function handleTaskError(data) {
    console.log('Task error:', data);
    
    hideLoadingModal();
    showToast('خطا در اجرای reconnaissance', 'error');
}

// Utility functions
function formatDate(dateString) {
    const date = new Date(dateString);
    return date.toLocaleDateString('fa-IR') + ' ' + date.toLocaleTimeString('fa-IR');
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function formatDuration(seconds) {
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const secs = seconds % 60;
    
    if (hours > 0) {
        return `${hours}:${minutes.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
    } else {
        return `${minutes}:${secs.toString().padStart(2, '0')}`;
    }
}

// Export functions for use in other scripts
window.ARAT = {
    showToast,
    showLoadingModal,
    hideLoadingModal,
    apiRequest,
    submitForm,
    formatDate,
    formatBytes,
    formatDuration
};