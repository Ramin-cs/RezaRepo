// Test script for improved image conversion
const fs = require('fs');
const path = require('path');
const FormData = require('form-data');
const fetch = require('node-fetch').default;

async function testImprovedConversion() {
    try {
        console.log('🎨 Testing Improved Image Conversion...\n');
        
        // Create a test image with clear structure
        const Jimp = require('jimp');
        
        // Create a 600x800 image with clear sections
        const image = new Jimp(600, 800, 0xFFFFFFFF); // White background
        
        // Header section (blue)
        for (let y = 0; y < 100; y++) {
            for (let x = 0; x < 600; x++) {
                image.setPixelColor(0x4F46E5FF, x, y); // Blue header
            }
        }
        
        // Main content area (light gray)
        for (let y = 100; y < 700; y++) {
            for (let x = 0; x < 600; x++) {
                image.setPixelColor(0xF8FAFCFF, x, y); // Light gray
            }
        }
        
        // Footer section (dark blue)
        for (let y = 700; y < 800; y++) {
            for (let x = 0; x < 600; x++) {
                image.setPixelColor(0x1E293BFF, x, y); // Dark blue
            }
        }
        
        // Add some clear text areas (dark rectangles)
        for (let y = 150; y < 180; y++) {
            for (let x = 50; x < 550; x++) {
                image.setPixelColor(0x000000FF, x, y); // Black text
            }
        }
        
        for (let y = 200; y < 230; y++) {
            for (let x = 50; x < 400; x++) {
                image.setPixelColor(0x374151FF, x, y); // Gray text
            }
        }
        
        // Add some clear image areas (colored rectangles)
        for (let y = 300; y < 450; y++) {
            for (let x = 50; x < 250; x++) {
                image.setPixelColor(0x10B981FF, x, y); // Green rectangle
            }
        }
        
        for (let y = 300; y < 450; y++) {
            for (let x = 300; x < 500; x++) {
                image.setPixelColor(0xF59E0BFF, x, y); // Orange rectangle
            }
        }
        
        // Add another text area
        for (let y = 500; y < 530; y++) {
            for (let x = 50; x < 550; x++) {
                image.setPixelColor(0x1F2937FF, x, y); // Dark gray text
            }
        }
        
        // Save the test image
        const testImagePath = path.join(__dirname, 'test-clear-layout.png');
        await image.writeAsync(testImagePath);
        
        console.log('✅ Test image created with clear structure');
        console.log('   - Blue header (100px height)');
        console.log('   - Light gray main area (600px height)');
        console.log('   - Dark blue footer (100px height)');
        console.log('   - Clear text areas (black and gray)');
        console.log('   - Two colored rectangles (green and orange)');
        
        // Test the conversion API
        const formData = new FormData();
        formData.append('image', fs.createReadStream(testImagePath), {
            filename: 'test-clear-layout.png',
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
        console.log('\n📊 Improved Analysis Results:');
        console.log(`   - Image dimensions: ${result.analysis.metadata.width}x${result.analysis.metadata.height}`);
        console.log(`   - Layout type: ${result.analysis.layout.type}`);
        console.log(`   - Sections detected: ${result.analysis.layout.sections.length}`);
        
        // Check sections
        result.analysis.layout.sections.forEach((section, index) => {
            console.log(`     ${index + 1}. ${section.type}: ${section.width}x${section.height} at (${section.x}, ${section.y})`);
        });
        
        console.log('\n🎨 Color Analysis:');
        console.log(`   - Dominant color: ${result.analysis.colors.dominant}`);
        console.log(`   - Color palette: ${result.analysis.colors.palette.length} colors`);
        
        console.log('\n📝 Text Detection:');
        console.log(`   - Text regions: ${result.analysis.text.length}`);
        result.analysis.text.forEach((text, index) => {
            console.log(`     ${index + 1}. ${text.type}: ${text.width}x${text.height} at (${text.x}, ${text.y}) - "${text.text}"`);
        });
        
        console.log('\n🖼️ Image Regions:');
        console.log(`   - Image regions: ${result.analysis.images.length}`);
        result.analysis.images.forEach((img, index) => {
            console.log(`     ${index + 1}. ${img.type}: ${img.width}x${img.height} at (${img.x}, ${img.y})`);
        });
        
        // Check if the HTML is improved
        const html = result.html;
        const textElementCount = (html.match(/text-element/g) || []).length;
        const imageElementCount = (html.match(/image-element/g) || []).length;
        const hasReasonableCount = textElementCount <= 10 && imageElementCount <= 5;
        
        console.log('\n🔍 Improvement Validation:');
        console.log(`   ${textElementCount <= 10 ? '✅' : '❌'} Text elements: ${textElementCount} (should be ≤ 10)`);
        console.log(`   ${imageElementCount <= 5 ? '✅' : '❌'} Image elements: ${imageElementCount} (should be ≤ 5)`);
        console.log(`   ${hasReasonableCount ? '✅' : '❌'} Overall element count: ${hasReasonableCount ? 'Good' : 'Too many'}`);
        
        // Check for reasonable dimensions
        const hasReasonableDimensions = result.analysis.text.every(t => t.width > 50 && t.height > 20) &&
                                      result.analysis.images.every(i => i.width > 80 && i.height > 60);
        
        console.log(`   ${hasReasonableDimensions ? '✅' : '❌'} Element dimensions: ${hasReasonableDimensions ? 'Reasonable' : 'Too small'}`);
        
        if (hasReasonableCount && hasReasonableDimensions) {
            console.log('\n🎉 Conversion is significantly improved!');
            console.log('   - Reasonable number of elements');
            console.log('   - Proper element dimensions');
            console.log('   - Clear layout structure');
        } else {
            console.log('\n⚠️ Conversion still needs improvement.');
        }
        
        // Save the result for inspection
        const outputDir = path.join(__dirname, 'improved-test');
        if (!fs.existsSync(outputDir)) {
            fs.mkdirSync(outputDir);
        }
        
        fs.writeFileSync(path.join(outputDir, 'index.html'), result.html);
        fs.writeFileSync(path.join(outputDir, 'styles.css'), result.css);
        fs.copyFileSync(testImagePath, path.join(outputDir, 'original-image.jpg'));
        
        console.log(`\n📁 Test files saved to: ${outputDir}`);
        console.log('   - index.html (improved HTML)');
        console.log('   - styles.css (improved CSS)');
        console.log('   - original-image.jpg (test image)');
        
        // Clean up
        fs.unlinkSync(testImagePath);
        console.log('\n🧹 Cleanup completed');
        
    } catch (error) {
        console.error('❌ Test failed:', error.message);
        process.exit(1);
    }
}

// Run the test
testImprovedConversion();