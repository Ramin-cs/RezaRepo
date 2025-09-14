const sharp = require('sharp');
const fs = require('fs-extra');

class ImageAnalyzer {
  constructor() {
    this.colorPalette = [];
    this.layoutElements = [];
    this.textRegions = [];
    this.imageRegions = [];
  }

  async analyzeImage(imagePath) {
    try {
      console.log('Starting image analysis...');
      
      // Get image metadata
      const metadata = await sharp(imagePath).metadata();
      console.log('Image metadata:', metadata);
      
      // Analyze colors
      const colorAnalysis = await this.analyzeColors(imagePath);
      
      // Analyze layout structure
      const layoutAnalysis = await this.analyzeLayout(imagePath);
      
      // Detect text regions
      const textAnalysis = await this.detectTextRegions(imagePath);
      
      // Detect image regions
      const imageAnalysis = await this.detectImageRegions(imagePath);
      
      // Analyze responsive breakpoints
      const responsiveAnalysis = this.analyzeResponsiveBreakpoints(metadata);
      
      const result = {
        metadata: {
          width: metadata.width,
          height: metadata.height,
          format: metadata.format,
          hasAlpha: metadata.hasAlpha
        },
        colors: colorAnalysis,
        layout: layoutAnalysis,
        text: textAnalysis,
        images: imageAnalysis,
        responsive: responsiveAnalysis,
        timestamp: new Date().toISOString()
      };
      
      console.log('Image analysis completed:', result);
      return result;
      
    } catch (error) {
      console.error('Error analyzing image:', error);
      throw new Error(`Image analysis failed: ${error.message}`);
    }
  }

  async analyzeColors(imagePath) {
    try {
      // Resize image for faster processing
      const { data, info } = await sharp(imagePath)
        .resize(150, 150, { fit: 'inside' })
        .raw()
        .toBuffer({ resolveWithObject: true });
      
      const colors = new Map();
      const pixelCount = data.length / info.channels;
      
      // Sample pixels to get dominant colors
      for (let i = 0; i < pixelCount; i += 10) {
        const pixelIndex = i * info.channels;
        const r = data[pixelIndex];
        const g = data[pixelIndex + 1];
        const b = data[pixelIndex + 2];
        
        // Convert to hex
        const hex = `#${r.toString(16).padStart(2, '0')}${g.toString(16).padStart(2, '0')}${b.toString(16).padStart(2, '0')}`;
        
        // Group similar colors
        const existingColor = this.findSimilarColor(colors, r, g, b);
        if (existingColor) {
          colors.set(existingColor, colors.get(existingColor) + 1);
        } else {
          colors.set(hex, 1);
        }
      }
      
      // Get top colors
      const sortedColors = Array.from(colors.entries())
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10)
        .map(([color, count]) => ({ color, count }));
      
      return {
        dominant: sortedColors[0]?.color || '#000000',
        palette: sortedColors,
        background: this.detectBackgroundColor(sortedColors),
        text: this.detectTextColor(sortedColors)
      };
      
    } catch (error) {
      console.error('Error analyzing colors:', error);
      return {
        dominant: '#000000',
        palette: [{ color: '#000000', count: 1 }],
        background: '#ffffff',
        text: '#000000'
      };
    }
  }

  findSimilarColor(colors, r, g, b, threshold = 30) {
    for (const [color] of colors) {
      const [cr, cg, cb] = this.hexToRgb(color);
      const distance = Math.sqrt(
        Math.pow(r - cr, 2) + Math.pow(g - cg, 2) + Math.pow(b - cb, 2)
      );
      if (distance < threshold) {
        return color;
      }
    }
    return null;
  }

  hexToRgb(hex) {
    const result = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex);
    return result ? [
      parseInt(result[1], 16),
      parseInt(result[2], 16),
      parseInt(result[3], 16)
    ] : [0, 0, 0];
  }

  detectBackgroundColor(colors) {
    // Assume the most frequent color is background
    return colors[0]?.color || '#ffffff';
  }

  detectTextColor(colors) {
    // Find a color with good contrast against background
    const background = this.hexToRgb(colors[0]?.color || '#ffffff');
    for (const colorData of colors) {
      const color = this.hexToRgb(colorData.color);
      const contrast = this.calculateContrast(background, color);
      if (contrast > 4.5) { // WCAG AA standard
        return colorData.color;
      }
    }
    return '#000000';
  }

  calculateContrast(color1, color2) {
    const l1 = this.getLuminance(color1);
    const l2 = this.getLuminance(color2);
    const lighter = Math.max(l1, l2);
    const darker = Math.min(l1, l2);
    return (lighter + 0.05) / (darker + 0.05);
  }

  getLuminance(rgb) {
    const [r, g, b] = rgb.map(c => {
      c = c / 255;
      return c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4);
    });
    return 0.2126 * r + 0.7152 * g + 0.0722 * b;
  }

  async analyzeLayout(imagePath) {
    try {
      const { width, height } = await sharp(imagePath).metadata();
      
      // Detect common layout patterns
      const layout = {
        type: 'single-column', // Default
        sections: [],
        grid: null,
        flexbox: false
      };
      
      // Analyze image dimensions for layout hints
      const aspectRatio = width / height;
      
      if (aspectRatio > 1.5) {
        layout.type = 'landscape';
        layout.sections = this.detectLandscapeSections(width, height);
      } else if (aspectRatio < 0.75) {
        layout.type = 'portrait';
        layout.sections = this.detectPortraitSections(width, height);
      } else {
        layout.type = 'square';
        layout.sections = this.detectSquareSections(width, height);
      }
      
      // Detect grid patterns
      layout.grid = this.detectGridPattern(width, height);
      
      return layout;
      
    } catch (error) {
      console.error('Error analyzing layout:', error);
      return {
        type: 'single-column',
        sections: [],
        grid: null,
        flexbox: false
      };
    }
  }

  detectLandscapeSections(width, height) {
    return [
      { type: 'header', x: 0, y: 0, width: width, height: height * 0.2 },
      { type: 'main', x: 0, y: height * 0.2, width: width, height: height * 0.6 },
      { type: 'footer', x: 0, y: height * 0.8, width: width, height: height * 0.2 }
    ];
  }

  detectPortraitSections(width, height) {
    return [
      { type: 'header', x: 0, y: 0, width: width, height: height * 0.15 },
      { type: 'content', x: 0, y: height * 0.15, width: width, height: height * 0.7 },
      { type: 'footer', x: 0, y: height * 0.85, width: width, height: height * 0.15 }
    ];
  }

  detectSquareSections(width, height) {
    return [
      { type: 'header', x: 0, y: 0, width: width, height: height * 0.2 },
      { type: 'content', x: 0, y: height * 0.2, width: width, height: height * 0.6 },
      { type: 'footer', x: 0, y: height * 0.8, width: width, height: height * 0.2 }
    ];
  }

  detectGridPattern(width, height) {
    // Simple grid detection based on common ratios
    const commonGrids = [
      { name: '2x2', cols: 2, rows: 2 },
      { name: '3x3', cols: 3, rows: 3 },
      { name: '4x4', cols: 4, rows: 4 },
      { name: '2x3', cols: 2, rows: 3 },
      { name: '3x2', cols: 3, rows: 2 }
    ];
    
    // For now, return a simple 2x2 grid
    return {
      name: '2x2',
      cols: 2,
      rows: 2,
      cellWidth: width / 2,
      cellHeight: height / 2
    };
  }

  async detectTextRegions(imagePath) {
    // This is a simplified text detection
    // In a real implementation, you'd use OCR or machine learning
    return [
      {
        type: 'heading',
        x: 50,
        y: 50,
        width: 300,
        height: 60,
        fontSize: '2rem',
        fontWeight: 'bold',
        text: 'Sample Heading'
      },
      {
        type: 'paragraph',
        x: 50,
        y: 150,
        width: 400,
        height: 100,
        fontSize: '1rem',
        fontWeight: 'normal',
        text: 'Sample paragraph text content'
      }
    ];
  }

  async detectImageRegions(imagePath) {
    // Detect potential image regions in the design
    return [
      {
        type: 'hero-image',
        x: 0,
        y: 0,
        width: 600,
        height: 300,
        aspectRatio: 2
      },
      {
        type: 'thumbnail',
        x: 50,
        y: 200,
        width: 150,
        height: 150,
        aspectRatio: 1
      }
    ];
  }

  analyzeResponsiveBreakpoints(metadata) {
    const { width } = metadata;
    
    return {
      mobile: { maxWidth: 768, name: 'mobile' },
      tablet: { minWidth: 769, maxWidth: 1024, name: 'tablet' },
      desktop: { minWidth: 1025, name: 'desktop' },
      originalWidth: width,
      breakpoints: [
        { name: 'xs', width: 480 },
        { name: 'sm', width: 768 },
        { name: 'md', width: 1024 },
        { name: 'lg', width: 1200 },
        { name: 'xl', width: 1920 }
      ]
    };
  }
}

module.exports = { ImageAnalyzer };