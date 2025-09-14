// Test script for advanced image conversion
const fs = require('fs');
const path = require('path');
const FormData = require('form-data');
const fetch = require('node-fetch').default;

async function testAdvancedConversion() {
    try {
        console.log('🚀 Testing Advanced Image Conversion...\n');
        
        // Create a test image with complex structure
        const Jimp = require('jimp');
        
        // Create a 800x1000 image with complex layout
        const image = new Jimp(800, 1000, 0xFFFFFFFF); // White background
        
        // Header section (gradient blue)
        for (let y = 0; y < 120; y++) {
            for (let x = 0; x < 800; x++) {
                const gradient = Math.floor((x / 800) * 255);
                image.setPixelColor(0x4F46E5FF | (gradient << 16), x, y);
            }
        }
        
        // Main content area (light gray with patterns)
        for (let y = 120; y < 880; y++) {
            for (let x = 0; x < 800; x++) {
                if ((x + y) % 20 < 10) {
                    image.setPixelColor(0xF8FAFCFF, x, y);
                } else {
                    image.setPixelColor(0xF1F5F9FF, x, y);
                }
            }
        }
        
        // Footer section (dark blue)
        for (let y = 880; y < 1000; y++) {
            for (let x = 0; x < 800; x++) {
                image.setPixelColor(0x1E293BFF, x, y);
            }
        }
        
        // Add complex text areas
        // Main heading
        for (let y = 150; y < 190; y++) {
            for (let x = 100; x < 700; x++) {
                image.setPixelColor(0x000000FF, x, y);
            }
        }
        
        // Subheading
        for (let y = 220; y < 250; y++) {
            for (let x = 100; x < 500; x++) {
                image.setPixelColor(0x374151FF, x, y);
            }
        }
        
        // Paragraph text
        for (let y = 280; y < 320; y++) {
            for (let x = 100; x < 700; x++) {
                image.setPixelColor(0x4B5563FF, x, y);
            }
        }
        
        // Add complex image areas with different colors
        // Hero image (green gradient)
        for (let y = 350; y < 550; y++) {
            for (let x = 100; x < 400; x++) {
                const gradient = Math.floor(((y - 350) / 200) * 100);
                image.setPixelColor(0x10B981FF | (gradient << 8), x, y);
            }
        }
        
        // Thumbnail 1 (orange)
        for (let y = 350; y < 450; y++) {
            for (let x = 450; x < 600; x++) {
                image.setPixelColor(0xF59E0BFF, x, y);
            }
        }
        
        // Thumbnail 2 (red)
        for (let y = 480; y < 580; y++) {
            for (let x = 450; x < 600; x++) {
                image.setPixelColor(0xEF4444FF, x, y);
            }
        }
        
        // Sidebar (purple)
        for (let y = 350; y < 700; y++) {
            for (let x = 650; x < 750; x++) {
                image.setPixelColor(0x8B5CF6FF, x, y);
            }
        }
        
        // Button-like areas
        for (let y = 600; y < 650; y++) {
            for (let x = 100; x < 250; x++) {
                image.setPixelColor(0x3B82F6FF, x, y);
            }
        }
        
        for (let y = 600; y < 650; y++) {
            for (let x = 280; x < 430; x++) {
                image.setPixelColor(0x06B6D4FF, x, y);
            }
        }
        
        // Additional text areas
        for (let y = 700; y < 740; y++) {
            for (let x = 100; x < 600; x++) {
                image.setPixelColor(0x1F2937FF, x, y);
            }
        }
        
        for (let y = 760; y < 800; y++) {
            for (let x = 100; x < 400; x++) {
                image.setPixelColor(0x374151FF, x, y);
            }
        }
        
        // Save the test image
        const testImagePath = path.join(__dirname, 'test-complex-layout.png');
        await image.writeAsync(testImagePath);
        
        console.log('✅ Complex test image created');
        console.log('   - Gradient header (120px height)');
        console.log('   - Patterned main area (760px height)');
        console.log('   - Dark footer (120px height)');
        console.log('   - Multiple text areas with different sizes');
        console.log('   - Hero image with gradient');
        console.log('   - Two thumbnail images');
        console.log('   - Sidebar section');
        console.log('   - Button-like areas');
        
        // Test the advanced conversion API
        const formData = new FormData();
        formData.append('image', fs.createReadStream(testImagePath), {
            filename: 'test-complex-layout.png',
            contentType: 'image/png'
        });
        
        console.log('\n📤 Sending request to Advanced API...');
        
        const response = await fetch('http://localhost:3000/api/convert-advanced', {
            method: 'POST',
            body: formData
        });
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        const result = await response.json();
        
        console.log('✅ Advanced API Response received');
        console.log('\n📊 Advanced Analysis Results:');
        console.log(`   - Image dimensions: ${result.analysis.metadata.width}x${result.analysis.metadata.height}`);
        console.log(`   - Layout type: ${result.analysis.layout.type}`);
        console.log(`   - Sections detected: ${result.analysis.layout.sections.length}`);
        
        // Check sections
        result.analysis.layout.sections.forEach((section, index) => {
            console.log(`     ${index + 1}. ${section.type}: ${section.width}x${section.height} at (${section.x}, ${section.y})`);
        });
        
        console.log('\n🎨 Advanced Color Analysis:');
        console.log(`   - Dominant color: ${result.analysis.colors.dominant}`);
        console.log(`   - Background color: ${result.analysis.colors.background}`);
        console.log(`   - Text color: ${result.analysis.colors.text}`);
        console.log(`   - Color palette: ${result.analysis.colors.palette.length} colors`);
        console.log(`   - Dark theme: ${result.analysis.colors.isDarkTheme}`);
        
        console.log('\n📝 Advanced Text Detection:');
        console.log(`   - Text regions: ${result.analysis.text.length}`);
        result.analysis.text.forEach((text, index) => {
            console.log(`     ${index + 1}. ${text.type}: ${text.width}x${text.height} at (${text.x}, ${text.y}) - "${text.text}"`);
        });
        
        console.log('\n🖼️ Advanced Image Regions:');
        console.log(`   - Image regions: ${result.analysis.images.length}`);
        result.analysis.images.forEach((img, index) => {
            console.log(`     ${index + 1}. ${img.type}: ${img.width}x${img.height} at (${img.x}, ${img.y}) - aspect ratio: ${img.aspectRatio}`);
        });
        
        console.log('\n🧩 Components Detection:');
        console.log(`   - Components: ${result.analysis.components.length}`);
        result.analysis.components.forEach((comp, index) => {
            console.log(`     ${index + 1}. ${comp.type}: ${comp.width}x${comp.height} at (${comp.x}, ${comp.y})`);
        });
        
        console.log('\n📱 Responsive Analysis:');
        console.log(`   - Mobile first: ${result.analysis.responsive.mobileFirst}`);
        console.log(`   - Tablet optimized: ${result.analysis.responsive.tabletOptimized}`);
        console.log(`   - Desktop optimized: ${result.analysis.responsive.desktopOptimized}`);
        console.log(`   - Breakpoints: ${Object.keys(result.analysis.responsive.breakpoints).join(', ')}`);
        
        // Check HTML improvements
        const html = result.html;
        const hasAdvancedFeatures = {
            semanticElements: html.includes('<header') || html.includes('<main') || html.includes('<footer'),
            interactiveElements: html.includes('interactive-element'),
            lazyLoading: html.includes('data-src'),
            animations: html.includes('transition') || html.includes('animation'),
            responsiveDesign: html.includes('@media'),
            modernCSS: html.includes('backdrop-filter') || html.includes('css custom properties'),
            accessibility: html.includes('aria-') || html.includes('role='),
            performance: html.includes('will-change') || html.includes('transform3d')
        };
        
        console.log('\n🔍 Advanced Features Validation:');
        Object.entries(hasAdvancedFeatures).forEach(([feature, present]) => {
            console.log(`   ${present ? '✅' : '❌'} ${feature}: ${present}`);
        });
        
        const advancedScore = Object.values(hasAdvancedFeatures).filter(Boolean).length;
        const totalFeatures = Object.keys(hasAdvancedFeatures).length;
        
        console.log(`\n📊 Advanced Features Score: ${advancedScore}/${totalFeatures} (${Math.round(advancedScore/totalFeatures*100)}%)`);
        
        if (advancedScore >= totalFeatures * 0.7) {
            console.log('\n🎉 Advanced conversion is working excellently!');
            console.log('   - Modern HTML5 semantic elements');
            console.log('   - Interactive components');
            console.log('   - Responsive design');
            console.log('   - Performance optimizations');
            console.log('   - Accessibility features');
        } else {
            console.log('\n⚠️ Advanced conversion needs more improvements.');
        }
        
        // Save the result for inspection
        const outputDir = path.join(__dirname, 'advanced-test');
        if (!fs.existsSync(outputDir)) {
            fs.mkdirSync(outputDir);
        }
        
        fs.writeFileSync(path.join(outputDir, 'index.html'), result.html);
        fs.writeFileSync(path.join(outputDir, 'styles.css'), result.css);
        fs.copyFileSync(testImagePath, path.join(outputDir, 'original-image.jpg'));
        
        console.log(`\n📁 Advanced test files saved to: ${outputDir}`);
        console.log('   - index.html (advanced HTML)');
        console.log('   - styles.css (advanced CSS)');
        console.log('   - original-image.jpg (test image)');
        
        // Clean up
        fs.unlinkSync(testImagePath);
        console.log('\n🧹 Cleanup completed');
        
    } catch (error) {
        console.error('❌ Advanced test failed:', error.message);
        process.exit(1);
    }
}

// Run the test
testAdvancedConversion();