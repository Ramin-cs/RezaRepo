// ARAT Web Panel - Phases Management JavaScript

let availablePhases = [];
let selectedPhases = [];
let currentTask = null;

// Initialize when document is ready
document.addEventListener('DOMContentLoaded', function() {
    loadAvailablePhases();
    initializeEventListeners();
    loadActiveTasks();
});

// Initialize event listeners
function initializeEventListeners() {
    // Select all phases checkbox
    const selectAllCheckbox = document.getElementById('select-all-phases');
    if (selectAllCheckbox) {
        selectAllCheckbox.addEventListener('change', function() {
            toggleAllPhases(this.checked);
        });
    }
    
    // Start reconnaissance button
    const startReconBtn = document.getElementById('start-recon');
    if (startReconBtn) {
        startReconBtn.addEventListener('click', startReconnaissance);
    }
    
    // Stop reconnaissance button
    const stopReconBtn = document.getElementById('stop-recon');
    if (stopReconBtn) {
        stopReconBtn.addEventListener('click', stopReconnaissance);
    }
    
    // Phase cards click handlers
    document.addEventListener('click', function(e) {
        if (e.target.closest('.phase-card')) {
            const phaseCard = e.target.closest('.phase-card');
            const phaseNumber = parseInt(phaseCard.dataset.phase);
            togglePhaseSelection(phaseNumber, phaseCard);
        }
    });
}

// Load available phases
async function loadAvailablePhases() {
    try {
        const response = await ARAT.apiRequest('/phases');
        if (response.success) {
            availablePhases = response.phases;
            renderPhaseCards();
            renderPhaseCheckboxes();
        } else {
            ARAT.showToast('خطا در بارگذاری فازها', 'error');
        }
    } catch (error) {
        console.error('Error loading phases:', error);
        ARAT.showToast('خطا در بارگذاری فازها', 'error');
    }
}

// Render phase cards
function renderPhaseCards() {
    const container = document.getElementById('phases-list');
    if (!container) return;
    
    container.innerHTML = availablePhases.map(phase => `
        <div class="col-md-6 col-lg-4 mb-3">
            <div class="card phase-card" data-phase="${phase.number}">
                <div class="card-body">
                    <div class="d-flex justify-content-between align-items-start mb-2">
                        <h6 class="card-title mb-0">${phase.name}</h6>
                        <span class="badge bg-secondary">${phase.number}</span>
                    </div>
                    <p class="card-text small text-muted">${phase.description}</p>
                    <div class="d-flex justify-content-between align-items-center">
                        <div class="form-check">
                            <input class="form-check-input phase-checkbox" type="checkbox" 
                                   value="${phase.number}" id="phase-${phase.number}">
                            <label class="form-check-label" for="phase-${phase.number}">
                                انتخاب
                            </label>
                        </div>
                        <div class="phase-status pending"></div>
                    </div>
                    ${phase.dependencies.length > 0 ? `
                        <small class="text-muted">
                            <i class="fas fa-link me-1"></i>
                            وابسته به: ${phase.dependencies.join(', ')}
                        </small>
                    ` : ''}
                </div>
            </div>
        </div>
    `).join('');
}

// Render phase checkboxes for modal
function renderPhaseCheckboxes() {
    const container = document.getElementById('phases-checkboxes');
    if (!container) return;
    
    container.innerHTML = availablePhases.map(phase => `
        <div class="form-check">
            <input class="form-check-input" type="checkbox" value="${phase.number}" 
                   id="modal-phase-${phase.number}">
            <label class="form-check-label" for="modal-phase-${phase.number}">
                ${phase.name} (فاز ${phase.number})
            </label>
        </div>
    `).join('');
    
    // Add event listeners to modal checkboxes
    container.querySelectorAll('input[type="checkbox"]').forEach(checkbox => {
        checkbox.addEventListener('change', function() {
            updateSelectedPhases();
        });
    });
}

// Toggle all phases selection
function toggleAllPhases(checked) {
    const checkboxes = document.querySelectorAll('.phase-checkbox, #phases-checkboxes input[type="checkbox"]');
    checkboxes.forEach(checkbox => {
        checkbox.checked = checked;
    });
    
    if (checked) {
        selectedPhases = availablePhases.map(phase => phase.number);
    } else {
        selectedPhases = [];
    }
    
    updatePhaseCardsSelection();
}

// Toggle phase selection
function togglePhaseSelection(phaseNumber, phaseCard) {
    const checkbox = phaseCard.querySelector('.phase-checkbox');
    if (checkbox) {
        checkbox.checked = !checkbox.checked;
        
        if (checkbox.checked) {
            selectedPhases.push(phaseNumber);
        } else {
            selectedPhases = selectedPhases.filter(p => p !== phaseNumber);
        }
        
        updatePhaseCardsSelection();
    }
}

// Update phase cards selection
function updatePhaseCardsSelection() {
    document.querySelectorAll('.phase-card').forEach(card => {
        const phaseNumber = parseInt(card.dataset.phase);
        if (selectedPhases.includes(phaseNumber)) {
            card.classList.add('selected');
        } else {
            card.classList.remove('selected');
        }
    });
}

// Update selected phases from modal checkboxes
function updateSelectedPhases() {
    const checkboxes = document.querySelectorAll('#phases-checkboxes input[type="checkbox"]:checked');
    selectedPhases = Array.from(checkboxes).map(cb => parseInt(cb.value));
    
    // Update select all checkbox
    const selectAllCheckbox = document.getElementById('select-all-phases');
    if (selectAllCheckbox) {
        selectAllCheckbox.checked = selectedPhases.length === availablePhases.length;
        selectAllCheckbox.indeterminate = selectedPhases.length > 0 && selectedPhases.length < availablePhases.length;
    }
}

// Start reconnaissance
async function startReconnaissance() {
    const target = document.getElementById('target').value.trim();
    const parallelExecution = document.getElementById('parallel-execution').checked;
    
    if (!target) {
        ARAT.showToast('لطفاً هدف را وارد کنید', 'warning');
        return;
    }
    
    if (selectedPhases.length === 0) {
        ARAT.showToast('لطفاً حداقل یک فاز انتخاب کنید', 'warning');
        return;
    }
    
    try {
        ARAT.showLoadingModal('شروع Reconnaissance', 'در حال شروع عملیات...');
        
        const response = await ARAT.apiRequest('/run', 'POST', {
            target: target,
            phases: selectedPhases,
            parallel: parallelExecution
        });
        
        if (response.success) {
            currentTask = {
                id: response.task_id,
                target: target,
                phases: selectedPhases,
                startTime: new Date()
            };
            
            // Join task room for real-time updates
            if (window.socket) {
                window.socket.emit('join_task', { task_id: response.task_id });
            }
            
            // Show progress modal
            showProgressModal();
            
            ARAT.hideLoadingModal();
            ARAT.showToast('Reconnaissance شروع شد', 'success');
            
            // Close run modal
            const runModal = bootstrap.Modal.getInstance(document.getElementById('runModal'));
            if (runModal) {
                runModal.hide();
            }
        } else {
            ARAT.hideLoadingModal();
            ARAT.showToast(response.error || 'خطا در شروع reconnaissance', 'error');
        }
    } catch (error) {
        console.error('Error starting reconnaissance:', error);
        ARAT.hideLoadingModal();
        ARAT.showToast('خطا در شروع reconnaissance', 'error');
    }
}

// Stop reconnaissance
async function stopReconnaissance() {
    if (!currentTask) {
        ARAT.showToast('هیچ task فعالی وجود ندارد', 'warning');
        return;
    }
    
    try {
        // TODO: Implement stop task API
        ARAT.showToast('توقف task در حال پیاده‌سازی است', 'info');
        
        // Leave task room
        if (window.socket) {
            window.socket.emit('leave_task', { task_id: currentTask.id });
        }
        
        currentTask = null;
        hideProgressModal();
        
    } catch (error) {
        console.error('Error stopping reconnaissance:', error);
        ARAT.showToast('خطا در توقف reconnaissance', 'error');
    }
}

// Show progress modal
function showProgressModal() {
    const modal = new bootstrap.Modal(document.getElementById('progressModal'));
    modal.show();
    
    // Update progress info
    const progressTarget = document.getElementById('progress-target');
    const progressPhase = document.getElementById('progress-phase');
    const currentStatus = document.getElementById('current-status');
    
    if (progressTarget && currentTask) {
        progressTarget.textContent = `هدف: ${currentTask.target}`;
    }
    
    if (progressPhase) {
        progressPhase.textContent = 'فاز: -';
    }
    
    if (currentStatus) {
        currentStatus.textContent = 'آماده برای شروع...';
    }
    
    // Clear results container
    const resultsContainer = document.getElementById('results-container');
    if (resultsContainer) {
        resultsContainer.innerHTML = '';
    }
}

// Hide progress modal
function hideProgressModal() {
    const modal = bootstrap.Modal.getInstance(document.getElementById('progressModal'));
    if (modal) {
        modal.hide();
    }
}

// Load active tasks
async function loadActiveTasks() {
    try {
        // TODO: Implement load active tasks API
        const container = document.getElementById('active-tasks');
        if (container) {
            container.innerHTML = `
                <div class="alert alert-info">
                    <i class="fas fa-info-circle me-2"></i>
                    در حال حاضر هیچ task فعالی وجود ندارد
                </div>
            `;
        }
    } catch (error) {
        console.error('Error loading active tasks:', error);
    }
}

// Handle phase status update
function updatePhaseStatus(phaseNumber, status) {
    const phaseCard = document.querySelector(`[data-phase="${phaseNumber}"]`);
    if (phaseCard) {
        const statusElement = phaseCard.querySelector('.phase-status');
        if (statusElement) {
            statusElement.className = `phase-status ${status}`;
        }
        
        // Update card appearance
        phaseCard.classList.remove('pending', 'running', 'completed', 'error');
        phaseCard.classList.add(status);
    }
}

// Handle task status update
function updateTaskStatus(taskId, status) {
    // TODO: Update task status in UI
    console.log(`Task ${taskId} status: ${status}`);
}

// Socket.IO event handlers for phases
if (window.socket) {
    window.socket.on('task_update', function(data) {
        if (currentTask && data.task_id === currentTask.id) {
            // Update progress bar
            const progressBar = document.getElementById('progress-bar');
            if (progressBar) {
                progressBar.style.width = `${data.progress}%`;
                progressBar.setAttribute('aria-valuenow', data.progress);
            }
            
            // Update current phase
            const progressPhase = document.getElementById('progress-phase');
            if (progressPhase && data.current_phase) {
                progressPhase.textContent = `فاز: ${data.current_phase}`;
                updatePhaseStatus(data.current_phase, 'running');
            }
            
            // Update status message
            const currentStatus = document.getElementById('current-status');
            if (currentStatus && data.message) {
                currentStatus.textContent = data.message;
            }
        }
    });
    
    window.socket.on('phase_completed', function(data) {
        if (currentTask && data.task_id === currentTask.id) {
            updatePhaseStatus(data.phase, 'completed');
            
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
        }
    });
    
    window.socket.on('phase_error', function(data) {
        if (currentTask && data.task_id === currentTask.id) {
            updatePhaseStatus(data.phase, 'error');
            
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
        }
    });
    
    window.socket.on('task_completed', function(data) {
        if (currentTask && data.task_id === currentTask.id) {
            // Update all selected phases to completed
            selectedPhases.forEach(phase => {
                updatePhaseStatus(phase, 'completed');
            });
            
            // Show completion message
            const currentStatus = document.getElementById('current-status');
            if (currentStatus) {
                currentStatus.textContent = 'Reconnaissance تکمیل شد!';
                currentStatus.className = 'alert alert-success';
            }
            
            // Update progress bar to 100%
            const progressBar = document.getElementById('progress-bar');
            if (progressBar) {
                progressBar.style.width = '100%';
                progressBar.setAttribute('aria-valuenow', 100);
            }
            
            ARAT.showToast('Reconnaissance تکمیل شد', 'success');
            
            // Auto-close modal after 3 seconds
            setTimeout(() => {
                hideProgressModal();
                currentTask = null;
                // Refresh the page or redirect to results
                window.location.href = '/reports';
            }, 3000);
        }
    });
    
    window.socket.on('task_error', function(data) {
        if (currentTask && data.task_id === currentTask.id) {
            // Update current status to error
            const currentStatus = document.getElementById('current-status');
            if (currentStatus) {
                currentStatus.textContent = `خطا: ${data.message}`;
                currentStatus.className = 'alert alert-danger';
            }
            
            ARAT.showToast('خطا در اجرای reconnaissance', 'error');
            
            // Auto-close modal after 5 seconds
            setTimeout(() => {
                hideProgressModal();
                currentTask = null;
            }, 5000);
        }
    });
}

// Export functions for global access
window.PhasesManager = {
    loadAvailablePhases,
    startReconnaissance,
    stopReconnaissance,
    updatePhaseStatus,
    updateTaskStatus
};