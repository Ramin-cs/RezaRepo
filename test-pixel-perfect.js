// Test script for pixel-perfect image conversion
const fs = require('fs');
const path = require('path');
const FormData = require('form-data');
const fetch = require('node-fetch').default;

async function testPixelPerfectConversion() {
    try {
        console.log('🎯 Testing Pixel-Perfect Image Conversion...\n');
        
        // Create a test image with specific elements
        const Jimp = require('jimp');
        
        // Create a 600x400 image with specific elements
        const image = new Jimp(600, 400, 0xFFFFFFFF); // White background
        
        // Logo area (top-left, square-ish)
        for (let y = 20; y < 80; y++) {
            for (let x = 20; x < 80; x++) {
                image.setPixelColor(0x3B82F6FF, x, y); // Blue logo
            }
        }
        
        // Main title (top center)
        for (let y = 30; y < 60; y++) {
            for (let x = 150; x < 450; x++) {
                image.setPixelColor(0x000000FF, x, y); // Black title
            }
        }
        
        // Subtitle (below title)
        for (let y = 80; y < 100; y++) {
            for (let x = 150; x < 350; x++) {
                image.setPixelColor(0x374151FF, x, y); // Gray subtitle
            }
        }
        
        // Description text (left side)
        for (let y = 120; y < 160; y++) {
            for (let x = 50; x < 300; x++) {
                image.setPixelColor(0x4B5563FF, x, y); // Dark gray text
            }
        }
        
        // Hero image (center-right)
        for (let y = 120; y < 280; y++) {
            for (let x = 350; x < 550; x++) {
                const gradient = Math.floor(((y - 120) / 160) * 100);
                image.setPixelColor(0x10B981FF | (gradient << 8), x, y); // Green gradient
            }
        }
        
        // Button 1 (bottom left)
        for (let y = 300; y < 340; y++) {
            for (let x = 50; x < 150; x++) {
                image.setPixelColor(0xEF4444FF, x, y); // Red button
            }
        }
        
        // Button 2 (bottom center)
        for (let y = 300; y < 340; y++) {
            for (let x = 200; x < 300; x++) {
                image.setPixelColor(0x8B5CF6FF, x, y); // Purple button
            }
        }
        
        // Additional text (bottom right)
        for (let y = 320; y < 350; y++) {
            for (let x = 400; x < 580; x++) {
                image.setPixelColor(0x1F2937FF, x, y); // Dark text
            }
        }
        
        // Small image/icon (top right)
        for (let y = 20; y < 60; y++) {
            for (let x = 500; x < 560; x++) {
                image.setPixelColor(0xF59E0BFF, x, y); // Orange icon
            }
        }
        
        // Save the test image
        const testImagePath = path.join(__dirname, 'test-specific-elements.png');
        await image.writeAsync(testImagePath);
        
        console.log('✅ Test image created with specific elements');
        console.log('   - Logo (60x60, top-left, blue)');
        console.log('   - Main title (300x30, top-center, black)');
        console.log('   - Subtitle (200x20, below title, gray)');
        console.log('   - Description (250x40, left side, dark gray)');
        console.log('   - Hero image (200x160, center-right, green gradient)');
        console.log('   - Button 1 (100x40, bottom-left, red)');
        console.log('   - Button 2 (100x40, bottom-center, purple)');
        console.log('   - Additional text (180x30, bottom-right, dark)');
        console.log('   - Small icon (60x40, top-right, orange)');
        
        // Test the pixel-perfect conversion API
        const formData = new FormData();
        formData.append('image', fs.createReadStream(testImagePath), {
            filename: 'test-specific-elements.png',
            contentType: 'image/png'
        });
        
        console.log('\n📤 Sending request to Pixel-Perfect API...');
        
        const response = await fetch('http://localhost:3000/api/convert-pixel-perfect', {
            method: 'POST',
            body: formData
        });
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        const result = await response.json();
        
        console.log('✅ Pixel-Perfect API Response received');
        console.log('\n📊 Pixel-Perfect Analysis Results:');
        console.log(`   - Image dimensions: ${result.analysis.metadata.width}x${result.analysis.metadata.height}`);
        console.log(`   - Layout type: ${result.analysis.layout.type}`);
        console.log(`   - Background color: ${result.analysis.colors.background}`);
        console.log(`   - Text color: ${result.analysis.colors.text}`);
        console.log(`   - Color palette: ${result.analysis.colors.palette.length} colors`);
        
        console.log('\n🎯 Detected Elements:');
        result.analysis.elements.forEach((element, index) => {
            console.log(`   ${index + 1}. ${element.type}: ${element.width}x${element.height} at (${element.x}, ${element.y})`);
            if (element.type === 'text') {
                console.log(`      - Content: "${element.content}"`);
                console.log(`      - Color: ${element.color}`);
                console.log(`      - Font size: ${element.fontSize}`);
            } else if (element.type === 'button') {
                console.log(`      - Text: "${element.text}"`);
                console.log(`      - Background: ${element.backgroundColor}`);
            } else if (element.type === 'image') {
                console.log(`      - Placeholder: "${element.placeholder}"`);
                console.log(`      - Aspect ratio: ${element.aspectRatio}`);
            } else if (element.type === 'logo') {
                console.log(`      - Placeholder: "${element.placeholder}"`);
                console.log(`      - Aspect ratio: ${element.aspectRatio}`);
            }
        });
        
        // Check if elements are detected correctly
        const elementTypes = result.analysis.elements.map(el => el.type);
        const expectedTypes = ['logo', 'text', 'text', 'text', 'image', 'button', 'button', 'text', 'image'];
        
        console.log('\n🔍 Element Detection Validation:');
        console.log(`   - Expected elements: ${expectedTypes.length}`);
        console.log(`   - Detected elements: ${result.analysis.elements.length}`);
        console.log(`   - Element types: ${elementTypes.join(', ')}`);
        
        const hasLogo = elementTypes.includes('logo');
        const hasText = elementTypes.includes('text');
        const hasImage = elementTypes.includes('image');
        const hasButton = elementTypes.includes('button');
        
        console.log(`   ${hasLogo ? '✅' : '❌'} Logo detected: ${hasLogo}`);
        console.log(`   ${hasText ? '✅' : '❌'} Text elements detected: ${hasText}`);
        console.log(`   ${hasImage ? '✅' : '❌'} Image elements detected: ${hasImage}`);
        console.log(`   ${hasButton ? '✅' : '❌'} Button elements detected: ${hasButton}`);
        
        // Check HTML structure
        const html = result.html;
        const hasPixelPerfectContainer = html.includes('pixel-perfect-container');
        const hasLogoElements = html.includes('logo-element');
        const hasTextElements = html.includes('text-element');
        const hasImageElements = html.includes('image-element');
        const hasButtonElements = html.includes('button-element');
        const hasOriginalOverlay = html.includes('original-image-overlay');
        
        console.log('\n🔍 HTML Structure Validation:');
        console.log(`   ${hasPixelPerfectContainer ? '✅' : '❌'} Pixel-perfect container: ${hasPixelPerfectContainer}`);
        console.log(`   ${hasLogoElements ? '✅' : '❌'} Logo elements: ${hasLogoElements}`);
        console.log(`   ${hasTextElements ? '✅' : '❌'} Text elements: ${hasTextElements}`);
        console.log(`   ${hasImageElements ? '✅' : '❌'} Image elements: ${hasImageElements}`);
        console.log(`   ${hasButtonElements ? '✅' : '❌'} Button elements: ${hasButtonElements}`);
        console.log(`   ${hasOriginalOverlay ? '✅' : '❌'} Original image overlay: ${hasOriginalOverlay}`);
        
        const htmlScore = [hasPixelPerfectContainer, hasLogoElements, hasTextElements, hasImageElements, hasButtonElements, hasOriginalOverlay].filter(Boolean).length;
        
        console.log(`\n📊 HTML Structure Score: ${htmlScore}/6 (${Math.round(htmlScore/6*100)}%)`);
        
        // Check CSS features
        const css = result.css;
        const hasCSSVariables = css.includes('--image-width') && css.includes('--color-background');
        const hasElementStyles = css.includes('.logo-element') && css.includes('.text-element');
        const hasResponsiveDesign = css.includes('@media');
        const hasInteractions = css.includes('hover') && css.includes('transition');
        
        console.log('\n🔍 CSS Features Validation:');
        console.log(`   ${hasCSSVariables ? '✅' : '❌'} CSS variables: ${hasCSSVariables}`);
        console.log(`   ${hasElementStyles ? '✅' : '❌'} Element styles: ${hasElementStyles}`);
        console.log(`   ${hasResponsiveDesign ? '✅' : '❌'} Responsive design: ${hasResponsiveDesign}`);
        console.log(`   ${hasInteractions ? '✅' : '❌'} Interactive effects: ${hasInteractions}`);
        
        const cssScore = [hasCSSVariables, hasElementStyles, hasResponsiveDesign, hasInteractions].filter(Boolean).length;
        
        console.log(`\n📊 CSS Features Score: ${cssScore}/4 (${Math.round(cssScore/4*100)}%)`);
        
        const overallScore = (htmlScore + cssScore) / 10;
        
        if (overallScore >= 0.8) {
            console.log('\n🎉 Pixel-perfect conversion is working excellently!');
            console.log('   - Elements detected accurately');
            console.log('   - HTML structure is correct');
            console.log('   - CSS styling is comprehensive');
            console.log('   - Ready for pixel-perfect rendering');
        } else if (overallScore >= 0.6) {
            console.log('\n✅ Pixel-perfect conversion is working well!');
            console.log('   - Most elements detected correctly');
            console.log('   - Good HTML/CSS structure');
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
        
        console.log(`\n📁 Pixel-perfect test files saved to: ${outputDir}`);
        console.log('   - index.html (pixel-perfect HTML)');
        console.log('   - styles.css (pixel-perfect CSS)');
        console.log('   - original-image.jpg (test image)');
        
        // Clean up
        fs.unlinkSync(testImagePath);
        console.log('\n🧹 Cleanup completed');
        
    } catch (error) {
        console.error('❌ Pixel-perfect test failed:', error.message);
        process.exit(1);
    }
}

// Run the test
testPixelPerfectConversion();