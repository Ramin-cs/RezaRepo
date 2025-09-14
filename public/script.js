// JavaScript برای صفحه اصلی
class ImageConverter {
    constructor() {
        console.log('🚀 ImageConverter initialized');
        this.initializeElements();
        this.setupEventListeners();
        console.log('✅ ImageConverter ready');
    }

    initializeElements() {
        console.log('🔍 Initializing DOM elements...');
        this.uploadArea = document.getElementById('uploadArea');
        this.imageInput = document.getElementById('imageInput');
        this.previewSection = document.getElementById('previewSection');
        this.previewImage = document.getElementById('previewImage');
        this.convertBtn = document.getElementById('convertBtn');
        this.loadingSection = document.getElementById('loadingSection');
        this.resultSection = document.getElementById('resultSection');
        this.errorSection = document.getElementById('errorSection');
        this.errorText = document.getElementById('errorText');
        this.imageDimensions = document.getElementById('imageDimensions');
        this.elementsCount = document.getElementById('elementsCount');
        this.mainColor = document.getElementById('mainColor');
        this.downloadHTML = document.getElementById('downloadHTML');
        this.downloadCSS = document.getElementById('downloadCSS');
        this.previewBtn = document.getElementById('previewBtn');
        
        // بررسی وجود elements
        const elements = {
            uploadArea: this.uploadArea,
            imageInput: this.imageInput,
            previewSection: this.previewSection,
            previewImage: this.previewImage,
            convertBtn: this.convertBtn,
            loadingSection: this.loadingSection,
            resultSection: this.resultSection,
            errorSection: this.errorSection,
            errorText: this.errorText,
            imageDimensions: this.imageDimensions,
            elementsCount: this.elementsCount,
            mainColor: this.mainColor,
            downloadHTML: this.downloadHTML,
            downloadCSS: this.downloadCSS,
            previewBtn: this.previewBtn
        };
        
        for (const [name, element] of Object.entries(elements)) {
            if (!element) {
                console.error(`❌ Element not found: ${name}`);
            } else {
                console.log(`✅ Element found: ${name}`);
            }
        }
    }

    setupEventListeners() {
        console.log('🔧 Setting up event listeners...');
        
        // کلیک روی آپلود
        this.uploadArea.addEventListener('click', () => {
            console.log('🖱️ Upload area clicked');
            this.imageInput.click();
        });

        // انتخاب فایل
        this.imageInput.addEventListener('change', (e) => {
            console.log('📁 File input changed:', e.target.files);
            this.handleFileSelect(e.target.files[0]);
        });

        // کشیدن و رها کردن
        this.uploadArea.addEventListener('dragover', (e) => {
            e.preventDefault();
            this.uploadArea.classList.add('dragover');
        });

        this.uploadArea.addEventListener('dragleave', () => {
            this.uploadArea.classList.remove('dragover');
        });

        this.uploadArea.addEventListener('drop', (e) => {
            e.preventDefault();
            this.uploadArea.classList.remove('dragover');
            this.handleFileSelect(e.dataTransfer.files[0]);
        });

        // دکمه تبدیل
        this.convertBtn.addEventListener('click', () => {
            this.convertImage();
        });

        // دکمه‌های دانلود
        this.downloadHTML.addEventListener('click', () => {
            this.downloadFile('index.html', this.resultHTML);
        });

        this.downloadCSS.addEventListener('click', () => {
            this.downloadFile('styles.css', this.resultCSS);
        });

        this.previewBtn.addEventListener('click', () => {
            this.previewResult();
        });
    }

    handleFileSelect(file) {
        console.log('📁 File selected:', file);
        if (!file) return;

        // بررسی نوع فایل
        if (!file.type.startsWith('image/')) {
            console.error('❌ Invalid file type:', file.type);
            this.showError('لطفاً یک فایل تصویری انتخاب کنید');
            return;
        }

        console.log('✅ Valid image file:', file.name, file.type, file.size);

        // نمایش پیش‌نمایش
        const reader = new FileReader();
        reader.onload = (e) => {
            console.log('🖼️ Image preview loaded');
            this.previewImage.src = e.target.result;
            this.previewSection.style.display = 'block';
            this.hideAllSections();
        };
        reader.readAsDataURL(file);

        this.selectedFile = file;
        console.log('💾 File stored for conversion');
    }

    async convertImage() {
        console.log('🔄 Starting conversion...');
        if (!this.selectedFile) {
            console.error('❌ No file selected');
            return;
        }

        console.log('📤 Uploading file:', this.selectedFile.name);
        this.showLoading();
        
        try {
            const formData = new FormData();
            formData.append('image', this.selectedFile);

            console.log('🌐 Sending request to /api/convert');
            const response = await fetch('/api/convert', {
                method: 'POST',
                body: formData
            });

            console.log('📥 Response received:', response.status, response.statusText);

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const result = await response.json();
            console.log('✅ Conversion result:', result);

            if (result.success) {
                this.showResult(result);
            } else {
                throw new Error(result.error || 'خطا در تبدیل عکس');
            }

        } catch (error) {
            console.error('❌ Conversion error:', error);
            this.showError('خطا در تبدیل عکس: ' + error.message);
        }
    }

    showResult(result) {
        this.resultHTML = result.html;
        this.resultCSS = result.css;
        this.resultAnalysis = result.analysis;

        // نمایش اطلاعات با error handling
        try {
            this.imageDimensions.textContent = `${result.analysis.width} × ${result.analysis.height} پیکسل`;
            this.elementsCount.textContent = result.analysis.elements ? result.analysis.elements.length : 0;
            this.mainColor.textContent = result.analysis.colors ? result.analysis.colors.primary : '#000000';
        } catch (error) {
            console.error('Error displaying result info:', error);
            this.imageDimensions.textContent = 'نامشخص';
            this.elementsCount.textContent = '0';
            this.mainColor.textContent = '#000000';
        }

        this.hideAllSections();
        this.resultSection.style.display = 'block';
    }

    showLoading() {
        this.hideAllSections();
        this.loadingSection.style.display = 'block';
    }

    showError(message) {
        this.errorText.textContent = message;
        this.hideAllSections();
        this.errorSection.style.display = 'block';
    }

    hideAllSections() {
        this.previewSection.style.display = 'none';
        this.loadingSection.style.display = 'none';
        this.resultSection.style.display = 'none';
        this.errorSection.style.display = 'none';
    }

    downloadFile(filename, content) {
        const blob = new Blob([content], { type: 'text/plain' });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        window.URL.revokeObjectURL(url);
    }

    previewResult() {
        // باز کردن پیش‌نمایش در تب جدید
        const previewWindow = window.open('', '_blank');
        previewWindow.document.write(this.resultHTML);
        previewWindow.document.close();
    }
}

// تابع ریست فرم
function resetForm() {
    const converter = window.imageConverter;
    converter.hideAllSections();
    converter.imageInput.value = '';
    converter.selectedFile = null;
    converter.previewImage.src = '';
}

// راه‌اندازی برنامه
document.addEventListener('DOMContentLoaded', () => {
    console.log('📄 DOM loaded, initializing ImageConverter...');
    window.imageConverter = new ImageConverter();
    console.log('🎉 ImageConverter created and ready!');
});

// نمایش پیام خوش‌آمدگویی
console.log('🖼️ تبدیل عکس به HTML/CSS آماده است!');