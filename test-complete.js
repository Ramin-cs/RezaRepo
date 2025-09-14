// Complete test suite for Image to HTML/CSS Converter
const fs = require('fs');
const path = require('path');
const FormData = require('form-data');
const fetch = require('node-fetch');

class ConverterTester {
    constructor() {
        this.baseUrl = 'http://localhost:3000';
        this.testResults = [];
    }

    async runAllTests() {
        console.log('🧪 Starting Complete Test Suite for Image to HTML/CSS Converter\n');
        
        try {
            await this.testServerHealth();
            await this.testImageUpload();
            await this.testImageAnalysis();
            await this.testCodeGeneration();
            await this.testPreviewSystem();
            await this.testDownloadFunctionality();
            
            this.printTestResults();
            
        } catch (error) {
            console.error('❌ Test suite failed:', error.message);
            process.exit(1);
        }
    }

    async testServerHealth() {
        console.log('🔍 Testing server health...');
        
        try {
            const response = await fetch(this.baseUrl);
            if (response.ok) {
                this.addTestResult('Server Health', 'PASS', 'Server is running and responding');
            } else {
                throw new Error(`Server returned status ${response.status}`);
            }
        } catch (error) {
            this.addTestResult('Server Health', 'FAIL', error.message);
            throw error;
        }
    }

    async testImageUpload() {
        console.log('📤 Testing image upload functionality...');
        
        try {
            // Create a test image
            const testImage = this.createTestImage();
            const formData = new FormData();
            formData.append('image', testImage, {
                filename: 'test-image.png',
                contentType: 'image/png'
            });
            
            const response = await fetch(`${this.baseUrl}/api/convert`, {
                method: 'POST',
                body: formData
            });
            
            if (!response.ok) {
                throw new Error(`Upload failed with status ${response.status}`);
            }
            
            const result = await response.json();
            
            if (result.success && result.html && result.css) {
                this.addTestResult('Image Upload', 'PASS', 'Image uploaded and processed successfully');
                this.testData = result;
            } else {
                throw new Error('Invalid response format');
            }
            
        } catch (error) {
            this.addTestResult('Image Upload', 'FAIL', error.message);
            throw error;
        }
    }

    async testImageAnalysis() {
        console.log('🔍 Testing image analysis...');
        
        try {
            const analysis = this.testData.analysis;
            
            // Check required analysis fields
            const requiredFields = ['metadata', 'colors', 'layout', 'text', 'images', 'responsive'];
            const missingFields = requiredFields.filter(field => !analysis[field]);
            
            if (missingFields.length > 0) {
                throw new Error(`Missing analysis fields: ${missingFields.join(', ')}`);
            }
            
            // Validate metadata
            if (!analysis.metadata.width || !analysis.metadata.height) {
                throw new Error('Invalid image metadata');
            }
            
            // Validate colors
            if (!analysis.colors.dominant || !analysis.colors.palette) {
                throw new Error('Invalid color analysis');
            }
            
            // Validate layout
            if (!analysis.layout.type || !Array.isArray(analysis.layout.sections)) {
                throw new Error('Invalid layout analysis');
            }
            
            this.addTestResult('Image Analysis', 'PASS', 'All analysis components working correctly');
            
        } catch (error) {
            this.addTestResult('Image Analysis', 'FAIL', error.message);
        }
    }

    async testCodeGeneration() {
        console.log('💻 Testing code generation...');
        
        try {
            const { html, css } = this.testData;
            
            // Test HTML generation
            if (!html.includes('<!DOCTYPE html>') || !html.includes('<html')) {
                throw new Error('Invalid HTML structure');
            }
            
            // Test CSS generation
            if (!css.includes(':root') || !css.includes('@media')) {
                throw new Error('Invalid CSS structure');
            }
            
            // Test responsive design
            if (!css.includes('@media (max-width: 767px)')) {
                throw new Error('Missing responsive breakpoints');
            }
            
            // Test modern CSS features
            if (!css.includes('display: grid') && !css.includes('display: flex')) {
                throw new Error('Missing modern CSS layout features');
            }
            
            this.addTestResult('Code Generation', 'PASS', 'HTML and CSS generated with modern features');
            
        } catch (error) {
            this.addTestResult('Code Generation', 'FAIL', error.message);
        }
    }

    async testPreviewSystem() {
        console.log('👁️ Testing preview system...');
        
        try {
            const previewUrl = this.testData.previewUrl;
            const response = await fetch(`${this.baseUrl}${previewUrl}`);
            
            if (!response.ok) {
                throw new Error(`Preview failed with status ${response.status}`);
            }
            
            const previewContent = await response.text();
            
            if (!previewContent.includes('<html') || !previewContent.includes('</html>')) {
                throw new Error('Invalid preview content');
            }
            
            this.addTestResult('Preview System', 'PASS', 'Preview system working correctly');
            
        } catch (error) {
            this.addTestResult('Preview System', 'FAIL', error.message);
        }
    }

    async testDownloadFunctionality() {
        console.log('💾 Testing download functionality...');
        
        try {
            // Test HTML download
            const downloadUrl = this.testData.previewUrl.replace('/preview/', '/api/download/');
            const response = await fetch(`${this.baseUrl}${downloadUrl}`);
            
            if (!response.ok) {
                throw new Error(`Download failed with status ${response.status}`);
            }
            
            this.addTestResult('Download Functionality', 'PASS', 'Download system working correctly');
            
        } catch (error) {
            this.addTestResult('Download Functionality', 'FAIL', error.message);
        }
    }

    createTestImage() {
        // Create a simple 100x100 PNG image
        const width = 100;
        const height = 100;
        
        // PNG header
        const pngSignature = Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
        
        // IHDR chunk
        const ihdrData = Buffer.alloc(13);
        ihdrData.writeUInt32BE(width, 0);
        ihdrData.writeUInt32BE(height, 4);
        ihdrData[8] = 8; // bit depth
        ihdrData[9] = 2; // color type (RGB)
        ihdrData[10] = 0; // compression
        ihdrData[11] = 0; // filter
        ihdrData[12] = 0; // interlace
        
        const ihdrChunk = this.createPNGChunk('IHDR', ihdrData);
        
        // IDAT chunk (minimal image data)
        const idatData = Buffer.alloc(width * height * 3 + height);
        for (let y = 0; y < height; y++) {
            idatData[y * (width * 3 + 1)] = 0; // filter type
            for (let x = 0; x < width; x++) {
                const pixelIndex = y * (width * 3 + 1) + 1 + x * 3;
                idatData[pixelIndex] = 255; // R
                idatData[pixelIndex + 1] = 0; // G
                idatData[pixelIndex + 2] = 0; // B
            }
        }
        
        const idatChunk = this.createPNGChunk('IDAT', idatData);
        
        // IEND chunk
        const iendChunk = this.createPNGChunk('IEND', Buffer.alloc(0));
        
        return Buffer.concat([pngSignature, ihdrChunk, idatChunk, iendChunk]);
    }

    createPNGChunk(type, data) {
        const length = Buffer.alloc(4);
        length.writeUInt32BE(data.length, 0);
        
        const typeBuffer = Buffer.from(type, 'ascii');
        const chunk = Buffer.concat([length, typeBuffer, data]);
        
        // Calculate CRC
        const crc = this.calculateCRC32(typeBuffer, data);
        const crcBuffer = Buffer.alloc(4);
        crcBuffer.writeUInt32BE(crc, 0);
        
        return Buffer.concat([chunk, crcBuffer]);
    }

    calculateCRC32(type, data) {
        // Simple CRC32 implementation
        const buffer = Buffer.concat([type, data]);
        let crc = 0xFFFFFFFF;
        
        for (let i = 0; i < buffer.length; i++) {
            crc ^= buffer[i];
            for (let j = 0; j < 8; j++) {
                crc = (crc >>> 1) ^ (crc & 1 ? 0xEDB88320 : 0);
            }
        }
        
        return (crc ^ 0xFFFFFFFF) >>> 0;
    }

    addTestResult(testName, status, message) {
        this.testResults.push({ testName, status, message });
        const icon = status === 'PASS' ? '✅' : '❌';
        console.log(`${icon} ${testName}: ${message}`);
    }

    printTestResults() {
        console.log('\n📊 Test Results Summary:');
        console.log('='.repeat(50));
        
        const passed = this.testResults.filter(r => r.status === 'PASS').length;
        const failed = this.testResults.filter(r => r.status === 'FAIL').length;
        const total = this.testResults.length;
        
        console.log(`Total Tests: ${total}`);
        console.log(`Passed: ${passed}`);
        console.log(`Failed: ${failed}`);
        console.log(`Success Rate: ${((passed / total) * 100).toFixed(1)}%`);
        
        if (failed > 0) {
            console.log('\n❌ Failed Tests:');
            this.testResults
                .filter(r => r.status === 'FAIL')
                .forEach(r => console.log(`   - ${r.testName}: ${r.message}`));
        }
        
        console.log('\n🎉 Test suite completed!');
        
        if (failed === 0) {
            console.log('✨ All tests passed! The system is working perfectly.');
        } else {
            console.log('⚠️  Some tests failed. Please check the issues above.');
            process.exit(1);
        }
    }
}

// Run the complete test suite
const tester = new ConverterTester();
tester.runAllTests();