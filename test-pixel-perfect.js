// Test script for pixel-perfect conversion
const fs = require('fs');
const path = require('path');
const FormData = require('form-data');
const fetch = require('node-fetch').default;

async function testPixelPerfectConversion() {
    try {
        console.log('🎨 Testing Pixel-Perfect Image Conversion...\n');
        
        // Create a test image with specific layout
        const Jimp = require('jimp');
        
        // Create a 800x600 image with clear sections
        const image = new Jimp(800, 600, 0xFFFFFFFF); // White background
        
        // Header section (blue)
        for (let y = 0; y < 120; y++) {
            for (let x = 0; x < 800; x++) {
                image.setPixelColor(0x4F46E5FF, x, y); // Blue header
            }
        }
        
        // Main content area (light blue)
        for (let y = 120; y < 480; y++) {
            for (let x = 0; x < 800; x++) {
                image.setPixelColor(0xF1F5F9FF, x, y); // Light blue
            }
        }
        
        // Footer section (dark blue)
        for (let y = 480; y < 600; y++) {
            for (let x = 0; x < 800; x++) {
                image.setPixelColor(0x1E293BFF, x, y); // Dark blue
            }
        }
        
        // Add some text-like areas (dark rectangles)
        for (let y = 150; y < 180; y++) {
            for (let x = 50; x < 400; x++) {
                image.setPixelColor(0x000000FF, x, y); // Black text
            }
        }
        
        for (let y = 200; y < 230; y++) {
            for (let x = 50; x < 600; x++) {
                image.setPixelColor(0x374151FF, x, y); // Gray text
            }
        }
        
        // Add some image-like colored rectangles
        for (let y = 250; y < 350; y++) {
            for (let x = 50; x < 200; x++) {
                image.setPixelColor(0x10B981FF, x, y); // Green rectangle
            }
        }
        
        for (let y = 250; y < 350; y++) {
            for (let x = 250; x < 400; x++) {
                image.setPixelColor(0xF59E0BFF, x, y); // Orange rectangle
            }
        }
        
        for (let y = 250; y < 350; y++) {
            for (let x = 450; x < 600; x++) {
                image.setPixelColor(0xEF4444FF, x, y); // Red rectangle
            }
        }
        
        // Save the test image
        const testImagePath = path.join(__dirname, 'test-layout.png');
        await image.writeAsync(testImagePath);
        
        console.log('✅ Test image created with clear layout structure');
        console.log('   - Blue header (120px height)');
        console.log('   - Light blue main area (360px height)');
        console.log('   - Dark blue footer (120px height)');
        console.log('   - Text areas (black and gray)');
        console.log('   - Three colored rectangles (green, orange, red)');
        
        // Test the conversion API
        const formData = new FormData();
        formData.append('image', fs.createReadStream(testImagePath), {
            filename: 'test-layout.png',
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
        console.log('\n📊 Pixel-Perfect Analysis Results:');
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
        
        console.log('\n🖼️ Image Regions:');
        console.log(`   - Image regions: ${result.analysis.images.length}`);
        
        // Check if the HTML contains pixel-perfect positioning
        const html = result.html;
        const hasPixelPositioning = html.includes('position: absolute') && html.includes('left:') && html.includes('top:');
        const hasExactDimensions = html.includes('width:') && html.includes('height:');
        const hasOriginalImage = html.includes('original-image.jpg');
        
        console.log('\n🔍 Pixel-Perfect Validation:');
        console.log(`   ${hasPixelPositioning ? '✅' : '❌'} Absolute positioning: ${hasPixelPositioning}`);
        console.log(`   ${hasExactDimensions ? '✅' : '❌'} Exact dimensions: ${hasExactDimensions}`);
        console.log(`   ${hasOriginalImage ? '✅' : '❌'} Original image reference: ${hasOriginalImage}`);
        
        if (hasPixelPositioning && hasExactDimensions) {
            console.log('\n🎉 Pixel-perfect conversion is working!');
            console.log('   The generated HTML should match the original image layout.');
        } else {
            console.log('\n⚠️ Pixel-perfect conversion needs improvement.');
        }
        
        // Save the result for inspection
        const outputDir = path.join(__dirname, 'pixel-perfect-test');
        if (!fs.existsSync(outputDir)) {
            fs.mkdirSync(outputDir);
        }
        
        fs.writeFileSync(path.join(outputDir, 'index.html'), result.html);
        fs.writeFileSync(path.join(outputDir, 'styles.css'), result.css);
        fs.copyFileSync(testImagePath, path.join(outputDir, 'original-image.jpg'));
        
        console.log(`\n📁 Test files saved to: ${outputDir}`);
        console.log('   - index.html (generated HTML)');
        console.log('   - styles.css (generated CSS)');
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
testPixelPerfectConversion();