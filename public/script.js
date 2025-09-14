class ImageConverter {
    constructor() {
        this.uploadArea = document.getElementById('uploadArea');
        this.fileInput = document.getElementById('fileInput');
        this.processingSection = document.getElementById('processingSection');
        this.resultsSection = document.getElementById('resultsSection');
        this.errorSection = document.getElementById('errorSection');
        this.toastContainer = document.getElementById('toastContainer');
        
        this.currentStep = 1;
        this.processingInterval = null;
        
        this.initializeEventListeners();
    }

    initializeEventListeners() {
        // Upload area events
        this.uploadArea.addEventListener('click', () => this.fileInput.click());
        this.uploadArea.addEventListener('dragover', this.handleDragOver.bind(this));
        this.uploadArea.addEventListener('dragleave', this.handleDragLeave.bind(this));
        this.uploadArea.addEventListener('drop', this.handleDrop.bind(this));
        
        // File input events
        this.fileInput.addEventListener('change', this.handleFileSelect.bind(this));
        
        // Preview controls
        document.getElementById('mobilePreview').addEventListener('click', () => this.setPreviewMode('mobile'));
        document.getElementById('tabletPreview').addEventListener('click', () => this.setPreviewMode('tablet'));
        document.getElementById('desktopPreview').addEventListener('click', () => this.setPreviewMode('desktop'));
        
        // Code tabs
        document.querySelectorAll('.tab-btn').forEach(btn => {
            btn.addEventListener('click', (e) => this.switchTab(e.target.dataset.tab));
        });
        
        // Copy buttons
        document.getElementById('copyHtml').addEventListener('click', () => this.copyToClipboard('html'));
        document.getElementById('copyCss').addEventListener('click', () => this.copyToClipboard('css'));
        
        // Action buttons
        document.getElementById('downloadZip').addEventListener('click', () => this.downloadFiles());
        document.getElementById('newConversion').addEventListener('click', () => this.resetConverter());
        document.getElementById('retryButton').addEventListener('click', () => this.resetConverter());
    }

    handleDragOver(e) {
        e.preventDefault();
        this.uploadArea.classList.add('dragover');
    }

    handleDragLeave(e) {
        e.preventDefault();
        this.uploadArea.classList.remove('dragover');
    }

    handleDrop(e) {
        e.preventDefault();
        this.uploadArea.classList.remove('dragover');
        
        const files = e.dataTransfer.files;
        if (files.length > 0) {
            this.processFile(files[0]);
        }
    }

    handleFileSelect(e) {
        const file = e.target.files[0];
        if (file) {
            this.processFile(file);
        }
    }

    processFile(file) {
        // Validate file type
        if (!this.isValidImageFile(file)) {
            this.showError('Please select a valid image file (JPG, PNG, GIF, or WebP).');
            return;
        }

        // Validate file size
        if (file.size > 10 * 1024 * 1024) {
            this.showError('File size must be less than 10MB.');
            return;
        }

        this.showProcessing();
        this.uploadFile(file);
    }

    isValidImageFile(file) {
        const validTypes = ['image/jpeg', 'image/jpg', 'image/png', 'image/gif', 'image/webp'];
        return validTypes.includes(file.type);
    }

    showProcessing() {
        this.hideAllSections();
        this.processingSection.style.display = 'block';
        this.startProcessingAnimation();
    }

    startProcessingAnimation() {
        this.currentStep = 1;
        this.updateProgressSteps();
        
        this.processingInterval = setInterval(() => {
            this.currentStep++;
            if (this.currentStep > 4) {
                this.currentStep = 1;
            }
            this.updateProgressSteps();
        }, 1500);
    }

    updateProgressSteps() {
        document.querySelectorAll('.step').forEach((step, index) => {
            if (index + 1 <= this.currentStep) {
                step.classList.add('active');
            } else {
                step.classList.remove('active');
            }
        });
    }

    async uploadFile(file) {
        const formData = new FormData();
        formData.append('image', file);

        try {
            const response = await fetch('/api/convert', {
                method: 'POST',
                body: formData
            });

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.error || 'Upload failed');
            }

            const result = await response.json();
            this.showResults(result);

        } catch (error) {
            console.error('Upload error:', error);
            this.showError(error.message || 'Failed to process image. Please try again.');
        }
    }

    showResults(result) {
        clearInterval(this.processingInterval);
        this.hideAllSections();
        this.resultsSection.style.display = 'block';

        // Set preview iframe
        const previewFrame = document.getElementById('previewFrame');
        previewFrame.src = result.previewUrl;

        // Set code content
        document.getElementById('htmlCode').textContent = result.html;
        document.getElementById('cssCode').textContent = result.css;

        // Display analysis
        this.displayAnalysis(result.analysis);

        // Store result for download
        this.currentResult = result;

        this.showToast('Conversion completed successfully!', 'success');
    }

    displayAnalysis(analysis) {
        // Color palette
        const colorPalette = document.getElementById('colorPalette');
        colorPalette.innerHTML = '';
        
        analysis.colors.palette.slice(0, 6).forEach(colorData => {
            const colorItem = document.createElement('div');
            colorItem.className = 'color-item';
            colorItem.innerHTML = `
                <div class="color-swatch" style="background-color: ${colorData.color}"></div>
                <span class="color-name">${colorData.color}</span>
            `;
            colorPalette.appendChild(colorItem);
        });

        // Layout info
        const layoutInfo = document.getElementById('layoutInfo');
        layoutInfo.innerHTML = `
            <p><strong>Type:</strong> ${analysis.layout.type}</p>
            <p><strong>Sections:</strong> ${analysis.layout.sections.length}</p>
            <p><strong>Grid:</strong> ${analysis.layout.grid ? analysis.layout.grid.name : 'None'}</p>
        `;

        // Breakpoints info
        const breakpointsInfo = document.getElementById('breakpointsInfo');
        breakpointsInfo.innerHTML = `
            <p><strong>Original Width:</strong> ${analysis.metadata.width}px</p>
            <p><strong>Original Height:</strong> ${analysis.metadata.height}px</p>
            <p><strong>Breakpoints:</strong> ${analysis.responsive.breakpoints.length} defined</p>
        `;
    }

    setPreviewMode(mode) {
        const previewFrame = document.getElementById('previewFrame');
        const buttons = document.querySelectorAll('.preview-controls .btn');
        
        buttons.forEach(btn => btn.classList.remove('active'));
        document.getElementById(`${mode}Preview`).classList.add('active');

        // Apply responsive styles to iframe
        const iframe = previewFrame.contentWindow;
        if (iframe) {
            const style = iframe.document.createElement('style');
            style.textContent = this.getResponsiveStyles(mode);
            iframe.document.head.appendChild(style);
        }
    }

    getResponsiveStyles(mode) {
        const styles = {
            mobile: `
                body { max-width: 375px; margin: 0 auto; }
                .container { padding: 0 1rem; }
                .hero-container { grid-template-columns: 1fr; }
                .grid-2x2, .grid-3x3, .grid-4x4 { grid-template-columns: 1fr; }
            `,
            tablet: `
                body { max-width: 768px; margin: 0 auto; }
                .hero-container { grid-template-columns: 1fr 1fr; }
                .grid-2x2 { grid-template-columns: repeat(2, 1fr); }
                .grid-3x3 { grid-template-columns: repeat(2, 1fr); }
            `,
            desktop: `
                body { max-width: 100%; }
                .hero-container { grid-template-columns: 1fr 1fr; }
                .grid-2x2 { grid-template-columns: repeat(2, 1fr); }
                .grid-3x3 { grid-template-columns: repeat(3, 1fr); }
                .grid-4x4 { grid-template-columns: repeat(4, 1fr); }
            `
        };
        return styles[mode] || '';
    }

    switchTab(tabName) {
        // Update tab buttons
        document.querySelectorAll('.tab-btn').forEach(btn => {
            btn.classList.remove('active');
        });
        document.querySelector(`[data-tab="${tabName}"]`).classList.add('active');

        // Update tab content
        document.querySelectorAll('.tab-content').forEach(content => {
            content.classList.remove('active');
        });
        document.getElementById(`${tabName}Tab`).classList.add('active');
    }

    async copyToClipboard(type) {
        const code = type === 'html' ? this.currentResult.html : this.currentResult.css;
        
        try {
            await navigator.clipboard.writeText(code);
            this.showToast(`${type.toUpperCase()} code copied to clipboard!`, 'success');
        } catch (error) {
            console.error('Copy failed:', error);
            this.showToast('Failed to copy code', 'error');
        }
    }

    downloadFiles() {
        if (!this.currentResult) {
            this.showToast('No files to download', 'error');
            return;
        }

        // Create a simple download link for HTML file
        const blob = new Blob([this.currentResult.html], { type: 'text/html' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'index.html';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);

        this.showToast('Files downloaded successfully!', 'success');
    }

    resetConverter() {
        this.hideAllSections();
        this.fileInput.value = '';
        this.currentResult = null;
        clearInterval(this.processingInterval);
        
        // Reset upload area
        this.uploadArea.classList.remove('dragover');
        
        // Reset tabs
        this.switchTab('html');
        
        // Reset preview mode
        this.setPreviewMode('desktop');
    }

    showError(message) {
        clearInterval(this.processingInterval);
        this.hideAllSections();
        this.errorSection.style.display = 'block';
        document.getElementById('errorMessage').textContent = message;
        this.showToast(message, 'error');
    }

    hideAllSections() {
        this.processingSection.style.display = 'none';
        this.resultsSection.style.display = 'none';
        this.errorSection.style.display = 'none';
    }

    showToast(message, type = 'success') {
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        
        const icon = type === 'success' ? 'check-circle' : 
                    type === 'error' ? 'exclamation-circle' : 
                    'info-circle';
        
        toast.innerHTML = `
            <i class="fas fa-${icon}"></i>
            <span>${message}</span>
        `;
        
        this.toastContainer.appendChild(toast);
        
        // Auto remove after 5 seconds
        setTimeout(() => {
            if (toast.parentNode) {
                toast.parentNode.removeChild(toast);
            }
        }, 5000);
    }
}

// Initialize the application when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new ImageConverter();
});

// Add some utility functions
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

// Add keyboard shortcuts
document.addEventListener('keydown', (e) => {
    // Ctrl/Cmd + U to focus upload area
    if ((e.ctrlKey || e.metaKey) && e.key === 'u') {
        e.preventDefault();
        document.getElementById('uploadArea').click();
    }
    
    // Escape to reset
    if (e.key === 'Escape') {
        const converter = window.imageConverter;
        if (converter) {
            converter.resetConverter();
        }
    }
});

// Add service worker for offline functionality (optional)
if ('serviceWorker' in navigator) {
    window.addEventListener('load', () => {
        navigator.serviceWorker.register('/sw.js')
            .then(registration => {
                console.log('SW registered: ', registration);
            })
            .catch(registrationError => {
                console.log('SW registration failed: ', registrationError);
            });
    });
}