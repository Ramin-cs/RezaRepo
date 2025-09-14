// Test script to verify real image analysis
const fs = require('fs');
const path = require('path');
const FormData = require('form-data');
const fetch = require('node-fetch').default;

async function testRealAnalysis() {
    try {
        console.log('🧪 Testing Real Image Analysis...\n');
        
        // Create a test image with specific colors
        const Jimp = require('jimp');
        
        // Create a 400x300 image with specific colors
        const image = new Jimp(400, 300, 0xFFFFFFFF); // White background
        
        // Add some colored rectangles to simulate a design
        // Header area (blue)
        for (let y = 0; y < 60; y++) {
            for (let x = 0; x < 400; x++) {
                image.setPixelColor(0x6366F1FF, x, y); // Blue
            }
        }
        
        // Main content area (light gray)
        for (let y = 60; y < 240; y++) {
            for (let x = 0; x < 400; x++) {
                image.setPixelColor(0xF8F9FAFF, x, y); // Light gray
            }
        }
        
        // Footer area (dark gray)
        for (let y = 240; y < 300; y++) {
            for (let x = 0; x < 400; x++) {
                image.setPixelColor(0x1E293BFF, x, y); // Dark gray
            }
        }
        
        // Add some text-like dark areas
        for (let y = 80; y < 100; y++) {
            for (let x = 50; x < 350; x++) {
                image.setPixelColor(0x000000FF, x, y); // Black text
            }
        }
        
        // Add some image-like colored areas
        for (let y = 120; y < 180; y++) {
            for (let x = 50; x < 150; x++) {
                image.setPixelColor(0x10B981FF, x, y); // Green
            }
        }
        
        for (let y = 120; y < 180; y++) {
            for (let x = 200; x < 300; x++) {
                image.setPixelColor(0xF59E0BFF, x, y); // Orange
            }
        }
        
        // Save the test image
        const testImagePath = path.join(__dirname, 'test-design.png');
        await image.writeAsync(testImagePath);
        
        console.log('✅ Test image created with specific colors and layout');
        console.log('   - Blue header (0x6366F1)');
        console.log('   - Light gray main area (0xF8F9FA)');
        console.log('   - Dark gray footer (0x1E293B)');
        console.log('   - Black text areas (0x000000)');
        console.log('   - Green and orange image areas');
        
        // Test the conversion API
        const formData = new FormData();
        formData.append('image', fs.createReadStream(testImagePath), {
            filename: 'test-design.png',
            contentType: 'image/png'
        });
        
        console.log('\n📤 Sending request to API...');
        
        const response = await fetch('http://localhost:3000/api/convert', {
            method: 'POST',
            body: formData
        });
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        const result = await response.json();
        
        console.log('✅ API Response received');
        console.log('\n📊 Analysis Results:');
        console.log(`   - Image dimensions: ${result.analysis.metadata.width}x${result.analysis.metadata.height}`);
        console.log(`   - Format: ${result.analysis.metadata.format}`);
        console.log(`   - Layout type: ${result.analysis.layout.type}`);
        console.log(`   - Sections detected: ${result.analysis.layout.sections.length}`);
        
        console.log('\n🎨 Color Analysis:');
        console.log(`   - Dominant color: ${result.analysis.colors.dominant}`);
        console.log(`   - Background color: ${result.analysis.colors.background}`);
        console.log(`   - Text color: ${result.analysis.colors.text}`);
        console.log(`   - Color palette: ${result.analysis.colors.palette.length} colors`);
        
        result.analysis.colors.palette.forEach((color, index) => {
            console.log(`     ${index + 1}. ${color.color} (count: ${color.count})`);
        });
        
        console.log('\n📝 Text Detection:');
        console.log(`   - Text regions detected: ${result.analysis.text.length}`);
        result.analysis.text.forEach((text, index) => {
            console.log(`     ${index + 1}. ${text.type} at (${text.x}%, ${text.y}%) - ${text.text}`);
        });
        
        console.log('\n🖼️ Image Regions:');
        console.log(`   - Image regions detected: ${result.analysis.images.length}`);
        result.analysis.images.forEach((img, index) => {
            console.log(`     ${index + 1}. ${img.type} at (${img.x}%, ${img.y}%) - ${img.width}x${img.height}%`);
        });
        
        console.log('\n📱 Responsive Analysis:');
        console.log(`   - Breakpoints: ${result.analysis.responsive.breakpoints.length}`);
        console.log(`   - Original width: ${result.analysis.responsive.originalWidth}px`);
        
        // Check if the analysis is working correctly
        const expectedColors = ['#6366f1', '#f8f9fa', '#1e293b', '#000000', '#10b981', '#f59e0b'];
        const detectedColors = result.analysis.colors.palette.map(c => c.color.toLowerCase());
        
        console.log('\n🔍 Validation:');
        let colorMatches = 0;
        expectedColors.forEach(expectedColor => {
            if (detectedColors.some(detected => detected.includes(expectedColor.replace('#', '')))) {
                colorMatches++;
                console.log(`   ✅ Found expected color: ${expectedColor}`);
            } else {
                console.log(`   ❌ Missing expected color: ${expectedColor}`);
            }
        });
        
        console.log(`\n📈 Color Detection Accuracy: ${(colorMatches / expectedColors.length * 100).toFixed(1)}%`);
        
        if (colorMatches >= expectedColors.length * 0.5) {
            console.log('\n🎉 Analysis is working correctly!');
            console.log('   The system is successfully detecting colors and layout from images.');
        } else {
            console.log('\n⚠️ Analysis needs improvement.');
            console.log('   Some colors are not being detected accurately.');
        }
        
        // Clean up
        fs.unlinkSync(testImagePath);
        console.log('\n🧹 Cleanup completed');
        
    } catch (error) {
        console.error('❌ Test failed:', error.message);
        process.exit(1);
    }
}

// Run the test
testRealAnalysis();