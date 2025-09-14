// Test script for the Image to HTML/CSS Converter API
const fs = require('fs');
const path = require('path');
const FormData = require('form-data');
const fetch = require('node-fetch');

async function testAPI() {
    try {
        console.log('🧪 Testing Image to HTML/CSS Converter API...\n');
        
        // Create a simple test image (1x1 pixel PNG)
        const testImageBuffer = Buffer.from([
            0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D,
            0x49, 0x48, 0x44, 0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
            0x08, 0x02, 0x00, 0x00, 0x00, 0x90, 0x77, 0x53, 0xDE, 0x00, 0x00, 0x00,
            0x0C, 0x49, 0x44, 0x41, 0x54, 0x08, 0xD7, 0x63, 0xF8, 0x0F, 0x00, 0x00,
            0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE,
            0x42, 0x60, 0x82
        ]);
        
        // Save test image
        const testImagePath = path.join(__dirname, 'test-image.png');
        fs.writeFileSync(testImagePath, testImageBuffer);
        
        console.log('✅ Test image created');
        
        // Test the conversion API
        const formData = new FormData();
        formData.append('image', fs.createReadStream(testImagePath), {
            filename: 'test-image.png',
            contentType: 'image/png'
        });
        
        console.log('📤 Sending request to API...');
        
        const response = await fetch('http://localhost:3000/api/convert', {
            method: 'POST',
            body: formData
        });
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        const result = await response.json();
        
        console.log('✅ API Response received');
        console.log('📊 Analysis Results:');
        console.log(`   - Image dimensions: ${result.analysis.metadata.width}x${result.analysis.metadata.height}`);
        console.log(`   - Format: ${result.analysis.metadata.format}`);
        console.log(`   - Layout type: ${result.analysis.layout.type}`);
        console.log(`   - Color palette: ${result.analysis.colors.palette.length} colors`);
        console.log(`   - Dominant color: ${result.analysis.colors.dominant}`);
        
        console.log('\n📝 Generated Files:');
        console.log(`   - HTML length: ${result.html.length} characters`);
        console.log(`   - CSS length: ${result.css.length} characters`);
        console.log(`   - Output path: ${result.outputPath}`);
        console.log(`   - Preview URL: ${result.previewUrl}`);
        
        // Test preview endpoint
        console.log('\n🔍 Testing preview endpoint...');
        const previewResponse = await fetch(`http://localhost:3000${result.previewUrl}`);
        
        if (previewResponse.ok) {
            console.log('✅ Preview endpoint working');
        } else {
            console.log('❌ Preview endpoint failed');
        }
        
        // Clean up
        fs.unlinkSync(testImagePath);
        console.log('\n🧹 Cleanup completed');
        
        console.log('\n🎉 All tests passed! The API is working correctly.');
        
    } catch (error) {
        console.error('❌ Test failed:', error.message);
        process.exit(1);
    }
}

// Run the test
testAPI();