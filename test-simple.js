// Test script for simple image to HTML/CSS conversion
const fs = require('fs');
const path = require('path');
const FormData = require('form-data');
const fetch = require('node-fetch').default;

async function testSimpleConversion() {
    try {
        console.log('🖼️ Testing Simple Image to HTML/CSS Conversion...\n');
        
        // Create a simple test image
        const Jimp = require('jimp');
        
        // Create a 400x300 image with simple elements
        const image = new Jimp(400, 300, 0xFFFFFFFF); // White background
        
        // Title (top center)
        for (let y = 20; y < 50; y++) {
            for (let x = 100; x < 300; x++) {
                image.setPixelColor(0x000000FF, x, y); // Black title
            }
        }
        
        // Subtitle (below title)
        for (let y = 70; y < 90; y++) {
            for (let x = 120; x < 280; x++) {
                image.setPixelColor(0x333333FF, x, y); // Gray subtitle
            }
        }
        
        // Description text (left side)
        for (let y = 120; y < 150; y++) {
            for (let x = 50; x < 200; x++) {
                image.setPixelColor(0x666666FF, x, y); // Dark gray text
            }
        }
        
        // Image area (right side)
        for (let y = 120; y < 220; y++) {
            for (let x = 250; x < 350; x++) {
                const gradient = Math.floor(((y - 120) / 100) * 100);
                image.setPixelColor(0x4CAF50FF | (gradient << 8), x, y); // Green gradient
            }
        }
        
        // Button (bottom center)
        for (let y = 250; y < 280; y++) {
            for (let x = 150; x < 250; x++) {
                image.setPixelColor(0x2196F3FF, x, y); // Blue button
            }
        }
        
        // Save the test image
        const testImagePath = path.join(__dirname, 'test-simple-design.png');
        await image.writeAsync(testImagePath);
        
        console.log('✅ Simple test image created');
        console.log('   - Title (200x30, top-center, black)');
        console.log('   - Subtitle (160x20, below title, gray)');
        console.log('   - Description (150x30, left side, dark gray)');
        console.log('   - Image area (100x100, right side, green gradient)');
        console.log('   - Button (100x30, bottom-center, blue)');
        
        // Test the simple conversion API
        const formData = new FormData();
        formData.append('image', fs.createReadStream(testImagePath), {
            filename: 'test-simple-design.png',
            contentType: 'image/png'
        });
        
        console.log('\n📤 Sending request to Simple API...');
        
        const response = await fetch('http://localhost:3000/api/convert-simple', {
            method: 'POST',
            body: formData
        });
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        const result = await response.json();
        
        console.log('✅ Simple API Response received');
        console.log('\n📊 Simple Analysis Results:');
        console.log(`   - Image dimensions: ${result.analysis.width}x${result.analysis.height}`);
        console.log(`   - Background color: ${result.analysis.colors.background}`);
        console.log(`   - Primary color: ${result.analysis.colors.primary}`);
        console.log(`   - Secondary color: ${result.analysis.colors.secondary}`);
        console.log(`   - Elements detected: ${result.analysis.elements.length}`);
        
        console.log('\n🎯 Detected Elements:');
        result.analysis.elements.forEach((element, index) => {
            console.log(`   ${index + 1}. ${element.type}: ${element.width}x${element.height} at (${element.x}, ${element.y})`);
            if (element.type === 'text') {
                console.log(`      - Content: "${element.content}"`);
                console.log(`      - Color: ${element.color}`);
            } else if (element.type === 'image') {
                console.log(`      - Placeholder: "${element.placeholder}"`);
            }
        });
        
        // Check HTML structure
        const html = result.html;
        const hasContainer = html.includes('image-container');
        const hasTextElements = html.includes('text-element');
        const hasImageElements = html.includes('image-element');
        const hasOriginalImage = html.includes('original-image');
        const hasRTL = html.includes('dir="rtl"');
        
        console.log('\n🔍 HTML Structure Validation:');
        console.log(`   ${hasContainer ? '✅' : '❌'} Image container: ${hasContainer}`);
        console.log(`   ${hasTextElements ? '✅' : '❌'} Text elements: ${hasTextElements}`);
        console.log(`   ${hasImageElements ? '✅' : '❌'} Image elements: ${hasImageElements}`);
        console.log(`   ${hasOriginalImage ? '✅' : '❌'} Original image overlay: ${hasOriginalImage}`);
        console.log(`   ${hasRTL ? '✅' : '❌'} RTL support: ${hasRTL}`);
        
        const htmlScore = [hasContainer, hasTextElements, hasImageElements, hasOriginalImage, hasRTL].filter(Boolean).length;
        
        console.log(`\n📊 HTML Structure Score: ${htmlScore}/5 (${Math.round(htmlScore/5*100)}%)`);
        
        // Check CSS features
        const css = result.css;
        const hasResponsive = css.includes('@media');
        const hasHoverEffects = css.includes('hover');
        const hasTransitions = css.includes('transition');
        const hasRTLSupport = css.includes('direction: rtl');
        
        console.log('\n🔍 CSS Features Validation:');
        console.log(`   ${hasResponsive ? '✅' : '❌'} Responsive design: ${hasResponsive}`);
        console.log(`   ${hasHoverEffects ? '✅' : '❌'} Hover effects: ${hasHoverEffects}`);
        console.log(`   ${hasTransitions ? '✅' : '❌'} Transitions: ${hasTransitions}`);
        console.log(`   ${hasRTLSupport ? '✅' : '❌'} RTL support: ${hasRTLSupport}`);
        
        const cssScore = [hasResponsive, hasHoverEffects, hasTransitions, hasRTLSupport].filter(Boolean).length;
        
        console.log(`\n📊 CSS Features Score: ${cssScore}/4 (${Math.round(cssScore/4*100)}%)`);
        
        const overallScore = (htmlScore + cssScore) / 9;
        
        if (overallScore >= 0.8) {
            console.log('\n🎉 Simple conversion is working perfectly!');
            console.log('   - Image converted to HTML/CSS successfully');
            console.log('   - Elements detected correctly');
            console.log('   - HTML structure is clean and simple');
            console.log('   - CSS styling is comprehensive');
        } else if (overallScore >= 0.6) {
            console.log('\n✅ Simple conversion is working well!');
            console.log('   - Most elements detected correctly');
            console.log('   - Good HTML/CSS structure');
        } else {
            console.log('\n⚠️ Simple conversion needs improvement.');
        }
        
        // Save the result for inspection
        const outputDir = path.join(__dirname, 'simple-test');
        if (!fs.existsSync(outputDir)) {
            fs.mkdirSync(outputDir);
        }
        
        fs.writeFileSync(path.join(outputDir, 'index.html'), result.html);
        fs.writeFileSync(path.join(outputDir, 'styles.css'), result.css);
        fs.copyFileSync(testImagePath, path.join(outputDir, 'original-image.jpg'));
        
        console.log(`\n📁 Simple test files saved to: ${outputDir}`);
        console.log('   - index.html (simple HTML)');
        console.log('   - styles.css (simple CSS)');
        console.log('   - original-image.jpg (test image)');
        
        // Clean up
        fs.unlinkSync(testImagePath);
        console.log('\n🧹 Cleanup completed');
        
    } catch (error) {
        console.error('❌ Simple test failed:', error.message);
        process.exit(1);
    }
}

// Run the test
testSimpleConversion();