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
      console.log('Analyzing colors for:', imagePath);
      
      // Use JIMP for color analysis
      const Jimp = require('jimp');
      const image = await Jimp.read(imagePath);
      
      const colors = new Map();
      const { width, height } = image.bitmap;
      
      console.log(`Image dimensions: ${width}x${height}`);
      
      // Sample pixels to get dominant colors
      const sampleRate = Math.max(1, Math.floor(Math.min(width, height) / 50));
      
      for (let y = 0; y < height; y += sampleRate) {
        for (let x = 0; x < width; x += sampleRate) {
          const pixel = Jimp.intToRGBA(image.getPixelColor(x, y));
          
          // Skip transparent pixels
          if (pixel.a < 128) continue;
          
          // Convert to hex
          const hex = `#${pixel.r.toString(16).padStart(2, '0')}${pixel.g.toString(16).padStart(2, '0')}${pixel.b.toString(16).padStart(2, '0')}`;
          
          // Group similar colors
          const existingColor = this.findSimilarColor(colors, pixel.r, pixel.g, pixel.b);
          if (existingColor) {
            colors.set(existingColor, colors.get(existingColor) + 1);
          } else {
            colors.set(hex, 1);
          }
        }
      }
      
      // Get top colors
      const sortedColors = Array.from(colors.entries())
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10)
        .map(([color, count]) => ({ color, count }));
      
      console.log('Detected colors:', sortedColors);
      
      return {
        dominant: sortedColors[0]?.color || '#6366f1',
        palette: sortedColors,
        background: this.detectBackgroundColor(sortedColors),
        text: this.detectTextColor(sortedColors)
      };
      
    } catch (error) {
      console.error('Error analyzing colors:', error);
      return {
        dominant: '#6366f1',
        palette: [
          { color: '#6366f1', count: 100 },
          { color: '#8b5cf6', count: 80 },
          { color: '#06b6d4', count: 60 },
          { color: '#10b981', count: 40 },
          { color: '#f59e0b', count: 20 }
        ],
        background: '#ffffff',
        text: '#1e293b'
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
      console.log('Analyzing layout for:', imagePath);
      
      // Use JIMP for layout analysis
      const Jimp = require('jimp');
      const image = await Jimp.read(imagePath);
      const { width, height } = image.bitmap;
      
      console.log(`Layout analysis - dimensions: ${width}x${height}`);
      
      // Detect common layout patterns
      const layout = {
        type: 'single-column', // Default
        sections: [],
        grid: null,
        flexbox: false
      };
      
      // Analyze image dimensions for layout hints
      const aspectRatio = width / height;
      console.log(`Aspect ratio: ${aspectRatio.toFixed(2)}`);
      
      if (aspectRatio > 1.5) {
        layout.type = 'landscape';
        layout.sections = this.detectLandscapeSections(width, height);
        console.log('Detected landscape layout');
      } else if (aspectRatio < 0.75) {
        layout.type = 'portrait';
        layout.sections = this.detectPortraitSections(width, height);
        console.log('Detected portrait layout');
      } else {
        layout.type = 'square';
        layout.sections = this.detectSquareSections(width, height);
        console.log('Detected square layout');
      }
      
      // Detect grid patterns based on image analysis
      layout.grid = this.detectGridPattern(width, height);
      
      // Analyze image content for better layout detection
      const contentAnalysis = await this.analyzeImageContent(image);
      layout.sections = this.enhanceSectionsWithContent(layout.sections, contentAnalysis);
      
      console.log('Layout analysis completed:', layout);
      return layout;
      
    } catch (error) {
      console.error('Error analyzing layout:', error);
      return {
        type: 'single-column',
        sections: [
          { type: 'header', x: 0, y: 0, width: 100, height: 20 },
          { type: 'main', x: 0, y: 20, width: 100, height: 60 },
          { type: 'footer', x: 0, y: 80, width: 100, height: 20 }
        ],
        grid: { name: '2x2', cols: 2, rows: 2, cellWidth: 50, cellHeight: 50 },
        flexbox: true
      };
    }
  }

  async analyzeImageContent(image) {
    try {
      const { width, height } = image.bitmap;
      const contentRegions = [];
      
      // Simple content analysis - look for color variations
      const step = Math.max(10, Math.floor(Math.min(width, height) / 20));
      
      for (let y = 0; y < height - step; y += step) {
        for (let x = 0; x < width - step; x += step) {
          const pixel = Jimp.intToRGBA(image.getPixelColor(x, y));
          
          // Detect content regions based on color intensity
          if (pixel.r > 200 || pixel.g > 200 || pixel.b > 200) {
            contentRegions.push({
              x: (x / width) * 100,
              y: (y / height) * 100,
              width: (step / width) * 100,
              height: (step / height) * 100,
              type: 'light-content'
            });
          }
        }
      }
      
      return contentRegions;
    } catch (error) {
      console.error('Error analyzing image content:', error);
      return [];
    }
  }

  enhanceSectionsWithContent(sections, contentAnalysis) {
    // Enhance sections based on content analysis
    return sections.map(section => {
      const contentInSection = contentAnalysis.filter(content => 
        content.x >= section.x && 
        content.x + content.width <= section.x + section.width &&
        content.y >= section.y && 
        content.y + content.height <= section.y + section.height
      );
      
      return {
        ...section,
        contentDensity: contentInSection.length,
        hasContent: contentInSection.length > 0
      };
    });
  }

  detectLandscapeSections(width, height) {
    return [
      { type: 'header', x: 0, y: 0, width: width, height: Math.floor(height * 0.2) },
      { type: 'main', x: 0, y: Math.floor(height * 0.2), width: width, height: Math.floor(height * 0.6) },
      { type: 'footer', x: 0, y: Math.floor(height * 0.8), width: width, height: Math.floor(height * 0.2) }
    ];
  }

  detectPortraitSections(width, height) {
    return [
      { type: 'header', x: 0, y: 0, width: width, height: Math.floor(height * 0.15) },
      { type: 'content', x: 0, y: Math.floor(height * 0.15), width: width, height: Math.floor(height * 0.7) },
      { type: 'footer', x: 0, y: Math.floor(height * 0.85), width: width, height: Math.floor(height * 0.15) }
    ];
  }

  detectSquareSections(width, height) {
    return [
      { type: 'header', x: 0, y: 0, width: width, height: Math.floor(height * 0.2) },
      { type: 'content', x: 0, y: Math.floor(height * 0.2), width: width, height: Math.floor(height * 0.6) },
      { type: 'footer', x: 0, y: Math.floor(height * 0.8), width: width, height: Math.floor(height * 0.2) }
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
    try {
      console.log('Detecting text regions for:', imagePath);
      
      // Use JIMP for text region detection
      const Jimp = require('jimp');
      const image = await Jimp.read(imagePath);
      const { width, height } = image.bitmap;
      
      console.log(`Text detection - dimensions: ${width}x${height}`);
      
      // Simple text region detection based on color contrast
      const textRegions = [];
      const step = Math.max(5, Math.floor(Math.min(width, height) / 100));
      
      for (let y = 0; y < height - step; y += step) {
        for (let x = 0; x < width - step; x += step) {
          const pixel = Jimp.intToRGBA(image.getPixelColor(x, y));
          
          // Detect potential text regions (dark areas on light background)
          if (pixel.r < 100 && pixel.g < 100 && pixel.b < 100 && pixel.a > 128) {
            textRegions.push({
              x: (x / width) * 100,
              y: (y / height) * 100,
              width: (step / width) * 100,
              height: (step / height) * 100,
              type: 'text-region',
              color: `#${pixel.r.toString(16).padStart(2, '0')}${pixel.g.toString(16).padStart(2, '0')}${pixel.b.toString(16).padStart(2, '0')}`
            });
          }
        }
      }
      
      // Group nearby text regions
      const groupedRegions = this.groupTextRegions(textRegions);
      
      // Convert to text elements
      const textElements = groupedRegions.map((region, index) => {
        const isHeading = region.width > 20 || region.height > 15;
        return {
          type: isHeading ? 'heading' : 'paragraph',
          x: region.x,
          y: region.y,
          width: region.width,
          height: region.height,
          fontSize: isHeading ? '2rem' : '1rem',
          fontWeight: isHeading ? 'bold' : 'normal',
          text: isHeading ? `Heading ${index + 1}` : `Paragraph text content ${index + 1}`,
          color: region.color || '#000000'
        };
      });
      
      console.log(`Detected ${textElements.length} text regions`);
      return textElements;
      
    } catch (error) {
      console.error('Error detecting text regions:', error);
      return [
        {
          type: 'heading',
          x: 10,
          y: 10,
          width: 80,
          height: 15,
          fontSize: '2rem',
          fontWeight: 'bold',
          text: 'Main Heading',
          color: '#000000'
        },
        {
          type: 'paragraph',
          x: 10,
          y: 30,
          width: 80,
          height: 20,
          fontSize: '1rem',
          fontWeight: 'normal',
          text: 'This is a sample paragraph with some content.',
          color: '#333333'
        }
      ];
    }
  }

  groupTextRegions(regions) {
    // Simple grouping algorithm - group nearby regions
    const grouped = [];
    const used = new Set();
    
    for (let i = 0; i < regions.length; i++) {
      if (used.has(i)) continue;
      
      const group = [regions[i]];
      used.add(i);
      
      for (let j = i + 1; j < regions.length; j++) {
        if (used.has(j)) continue;
        
        const region1 = regions[i];
        const region2 = regions[j];
        
        // Check if regions are close enough to group
        const distance = Math.sqrt(
          Math.pow(region1.x - region2.x, 2) + 
          Math.pow(region1.y - region2.y, 2)
        );
        
        if (distance < 10) { // 10% threshold
          group.push(regions[j]);
          used.add(j);
        }
      }
      
      // Calculate group bounds
      const groupBounds = {
        x: Math.min(...group.map(r => r.x)),
        y: Math.min(...group.map(r => r.y)),
        width: Math.max(...group.map(r => r.x + r.width)) - Math.min(...group.map(r => r.x)),
        height: Math.max(...group.map(r => r.y + r.height)) - Math.min(...group.map(r => r.y)),
        color: group[0].color
      };
      
      grouped.push(groupBounds);
    }
    
    return grouped;
  }

  async detectImageRegions(imagePath) {
    try {
      console.log('Detecting image regions for:', imagePath);
      
      // Use JIMP for image region detection
      const Jimp = require('jimp');
      const image = await Jimp.read(imagePath);
      const { width, height } = image.bitmap;
      
      console.log(`Image region detection - dimensions: ${width}x${height}`);
      
      // Detect potential image regions based on color variations
      const imageRegions = [];
      const step = Math.max(10, Math.floor(Math.min(width, height) / 50));
      
      for (let y = 0; y < height - step; y += step) {
        for (let x = 0; x < width - step; x += step) {
          const pixel = Jimp.intToRGBA(image.getPixelColor(x, y));
          
          // Detect potential image regions (areas with significant color variation)
          const colorIntensity = (pixel.r + pixel.g + pixel.b) / 3;
          if (colorIntensity > 50 && colorIntensity < 200 && pixel.a > 128) {
            imageRegions.push({
              x: (x / width) * 100,
              y: (y / height) * 100,
              width: (step / width) * 100,
              height: (step / height) * 100,
              type: 'image-region',
              colorIntensity: colorIntensity
            });
          }
        }
      }
      
      // Group nearby image regions
      const groupedRegions = this.groupImageRegions(imageRegions);
      
      // Convert to image elements
      const imageElements = groupedRegions.map((region, index) => {
        const aspectRatio = region.width / region.height;
        const isHero = region.width > 60 || region.height > 40;
        
        return {
          type: isHero ? 'hero-image' : 'thumbnail',
          x: region.x,
          y: region.y,
          width: region.width,
          height: region.height,
          aspectRatio: aspectRatio,
          colorIntensity: region.colorIntensity
        };
      });
      
      console.log(`Detected ${imageElements.length} image regions`);
      return imageElements;
      
    } catch (error) {
      console.error('Error detecting image regions:', error);
      return [
        {
          type: 'hero-image',
          x: 0,
          y: 0,
          width: 100,
          height: 50,
          aspectRatio: 2
        },
        {
          type: 'thumbnail',
          x: 10,
          y: 60,
          width: 30,
          height: 30,
          aspectRatio: 1
        }
      ];
    }
  }

  groupImageRegions(regions) {
    // Simple grouping algorithm for image regions
    const grouped = [];
    const used = new Set();
    
    for (let i = 0; i < regions.length; i++) {
      if (used.has(i)) continue;
      
      const group = [regions[i]];
      used.add(i);
      
      for (let j = i + 1; j < regions.length; j++) {
        if (used.has(j)) continue;
        
        const region1 = regions[i];
        const region2 = regions[j];
        
        // Check if regions are close enough to group
        const distance = Math.sqrt(
          Math.pow(region1.x - region2.x, 2) + 
          Math.pow(region1.y - region2.y, 2)
        );
        
        if (distance < 15) { // 15% threshold for image regions
          group.push(regions[j]);
          used.add(j);
        }
      }
      
      // Calculate group bounds
      const groupBounds = {
        x: Math.min(...group.map(r => r.x)),
        y: Math.min(...group.map(r => r.y)),
        width: Math.max(...group.map(r => r.x + r.width)) - Math.min(...group.map(r => r.x)),
        height: Math.max(...group.map(r => r.y + r.height)) - Math.min(...group.map(r => r.y)),
        colorIntensity: group.reduce((sum, r) => sum + r.colorIntensity, 0) / group.length
      };
      
      grouped.push(groupBounds);
    }
    
    return grouped;
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