// JavaScript برای صفحه اصلی
class ImageConverter {
    constructor() {
        this.initializeElements();
        this.setupEventListeners();
    }

    initializeElements() {
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
    }

    setupEventListeners() {
        // کلیک روی آپلود
        this.uploadArea.addEventListener('click', () => {
            this.imageInput.click();
        });

        // انتخاب فایل
        this.imageInput.addEventListener('change', (e) => {
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
        if (!file) return;

        // بررسی نوع فایل
        if (!file.type.startsWith('image/')) {
            this.showError('لطفاً یک فایل تصویری انتخاب کنید');
            return;
        }

        // نمایش پیش‌نمایش
        const reader = new FileReader();
        reader.onload = (e) => {
            this.previewImage.src = e.target.result;
            this.previewSection.style.display = 'block';
            this.hideAllSections();
        };
        reader.readAsDataURL(file);

        this.selectedFile = file;
    }

    async convertImage() {
        if (!this.selectedFile) return;

        this.showLoading();
        
        try {
            const formData = new FormData();
            formData.append('image', this.selectedFile);

            const response = await fetch('/api/convert', {
                method: 'POST',
                body: formData
            });

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const result = await response.json();

            if (result.success) {
                this.showResult(result);
            } else {
                throw new Error(result.error || 'خطا در تبدیل عکس');
            }

        } catch (error) {
            console.error('Conversion error:', error);
            this.showError('خطا در تبدیل عکس: ' + error.message);
        }
    }

    showResult(result) {
        this.resultHTML = result.html;
        this.resultCSS = result.css;
        this.resultAnalysis = result.analysis;

        // نمایش اطلاعات
        this.imageDimensions.textContent = `${result.analysis.width} × ${result.analysis.height} پیکسل`;
        this.elementsCount.textContent = result.analysis.elements.length;
        this.mainColor.textContent = result.analysis.colors.primary;

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
    window.imageConverter = new ImageConverter();
});

// نمایش پیام خوش‌آمدگویی
console.log('🖼️ تبدیل عکس به HTML/CSS آماده است!');