const { AdvancedImageAnalyzer } = require('./advancedImageAnalyzer');
const { AIHTMLGenerator } = require('./aiHTMLGenerator');
const { AdvancedCSSGenerator } = require('./advancedCSSGenerator');

class AdvancedImageConverter {
  constructor() {
    this.analyzer = new AdvancedImageAnalyzer();
    this.htmlGenerator = new AIHTMLGenerator();
    this.cssGenerator = new AdvancedCSSGenerator();
  }

  async convertImageToHTMLCSS(imagePath) {
    console.log('🚀 Starting advanced image conversion...');
    
    try {
      // Step 1: Advanced Image Analysis
      console.log('📊 Step 1: Analyzing image with AI...');
      const analysis = await this.analyzer.analyzeImage(imagePath);
      
      // Step 2: Generate AI-powered HTML
      console.log('🤖 Step 2: Generating semantic HTML...');
      const html = this.htmlGenerator.generateHTML(analysis);
      
      // Step 3: Generate advanced CSS
      console.log('🎨 Step 3: Generating responsive CSS...');
      const css = this.cssGenerator.generateCSS(analysis);
      
      // Step 4: Prepare result
      const result = {
        html,
        css,
        analysis: {
          imageInfo: analysis.imageInfo,
          totalElements: analysis.analysis.totalElements,
          textElements: analysis.analysis.textElements,
          imageElements: analysis.analysis.imageElements,
          layoutType: analysis.analysis.layoutType,
          dominantColors: analysis.analysis.dominantColors,
          hasHeader: analysis.layout.hasHeader,
          hasFooter: analysis.layout.hasFooter,
          columns: analysis.layout.columns
        },
        metadata: {
          generatedAt: new Date().toISOString(),
          version: '2.0.0',
          features: [
            'OCR Text Detection',
            'Edge Detection',
            'Layout Analysis',
            'Color Palette Extraction',
            'Semantic HTML Generation',
            'Responsive CSS',
            'AI-Powered Classification'
          ]
        }
      };
      
      console.log('✅ Advanced conversion completed successfully!');
      console.log(`📈 Analysis Results:`);
      console.log(`   - Total Elements: ${result.analysis.totalElements}`);
      console.log(`   - Text Elements: ${result.analysis.textElements}`);
      console.log(`   - Image Elements: ${result.analysis.imageElements}`);
      console.log(`   - Layout Type: ${result.analysis.layoutType}`);
      console.log(`   - Has Header: ${result.analysis.hasHeader}`);
      console.log(`   - Has Footer: ${result.analysis.hasFooter}`);
      
      return result;
      
    } catch (error) {
      console.error('❌ Advanced conversion failed:', error);
      
      // Fallback to basic conversion
      console.log('🔄 Falling back to basic conversion...');
      return await this.fallbackConversion(imagePath);
    }
  }

  async fallbackConversion(imagePath) {
    const Jimp = require('jimp');
    
    try {
      const image = await Jimp.read(imagePath);
      const { width, height } = image.bitmap;
      
      // Basic color extraction
      const colorMap = new Map();
      const step = Math.max(10, Math.floor(Math.min(width, height) / 50));
      
      for (let y = 0; y < height; y += step) {
        for (let x = 0; x < width; x += step) {
          const pixel = Jimp.intToRGBA(image.getPixelColor(x, y));
          const color = `#${pixel.r.toString(16).padStart(2, '0')}${pixel.g.toString(16).padStart(2, '0')}${pixel.b.toString(16).padStart(2, '0')}`;
          colorMap.set(color, (colorMap.get(color) || 0) + 1);
        }
      }
      
      const sortedColors = Array.from(colorMap.entries())
        .sort((a, b) => b[1] - a[1])
        .map(([color]) => color);
      
      const colors = {
        background: sortedColors[0] || '#ffffff',
        primary: sortedColors[1] || '#000000',
        secondary: sortedColors[2] || '#cccccc',
        palette: sortedColors.slice(0, 5)
      };
      
      // Basic HTML
      const html = `<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>صفحه تبدیل شده از عکس</title>
    <link rel="stylesheet" href="styles.css">
</head>
<body>
    <div class="image-container" style="width: ${width}px; height: ${height}px; background-color: ${colors.background};">
        <div class="fallback-content" style="position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); text-align: center; color: ${colors.primary};">
            <h1>محتوای عکس</h1>
            <p>ابعاد: ${width} × ${height} پیکسل</p>
        </div>
        <div class="original-image" style="position: absolute; top: 0; left: 0; width: 100%; height: 100%; background-image: url('original-image.jpg'); background-size: contain; background-repeat: no-repeat; background-position: center; opacity: 0.1; pointer-events: none;"></div>
    </div>
</body>
</html>`;
      
      // Basic CSS
      const css = `/* Basic CSS - Fallback Mode */
* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: 'Tahoma', 'Arial', sans-serif;
    background-color: #f5f5f5;
    padding: 20px;
    direction: rtl;
}

.image-container {
    position: relative;
    margin: 0 auto;
    border: 2px solid #ddd;
    border-radius: 8px;
    box-shadow: 0 4px 8px rgba(0,0,0,0.1);
    overflow: hidden;
}

.fallback-content {
    font-size: 18px;
    font-weight: bold;
}

.original-image {
    z-index: 1;
}

@media (max-width: 768px) {
    .image-container {
        width: 100% !important;
        height: auto !important;
    }
}`;
      
      return {
        html,
        css,
        analysis: {
          imageInfo: { width, height },
          totalElements: 1,
          textElements: 1,
          imageElements: 0,
          layoutType: 'fallback',
          dominantColors: colors.palette,
          hasHeader: false,
          hasFooter: false,
          columns: 1
        },
        metadata: {
          generatedAt: new Date().toISOString(),
          version: '1.0.0-fallback',
          features: ['Basic Color Extraction', 'Fallback Mode']
        }
      };
      
    } catch (error) {
      console.error('❌ Fallback conversion also failed:', error);
      throw new Error('Both advanced and fallback conversions failed');
    }
  }

  async cleanup() {
    if (this.analyzer) {
      await this.analyzer.cleanup();
    }
  }
}

module.exports = { AdvancedImageConverter };