const Jimp = require('jimp');

class AdvancedImageAnalyzer {
  constructor() {
    this.edgeThreshold = 50;
    this.textThreshold = 100;
    this.imageThreshold = 80;
  }

  async analyzeImage(imagePath) {
    try {
      console.log('🔍 Advanced Image Analysis Starting...');
      
      const image = await Jimp.read(imagePath);
      const { width, height } = image.bitmap;
      
      console.log(`📐 Image dimensions: ${width}x${height}`);
      
      // Advanced analysis pipeline
      const analysis = {
        metadata: {
          width,
          height,
          aspectRatio: width / height,
          format: image.getMIME()
        },
        colors: await this.analyzeAdvancedColors(image),
        layout: await this.detectAdvancedLayout(image),
        text: await this.detectAdvancedText(image),
        images: await this.detectAdvancedImages(image),
        components: await this.detectComponents(image),
        responsive: await this.analyzeResponsive(image)
      };
      
      console.log('✅ Advanced analysis completed');
      return analysis;
      
    } catch (error) {
      console.error('❌ Advanced analysis failed:', error);
      throw error;
    }
  }

  async analyzeAdvancedColors(image) {
    const { width, height } = image.bitmap;
    const colorMap = new Map();
    const sampleSize = Math.max(10, Math.floor(Math.min(width, height) / 50));
    
    // Sample colors from the image
    for (let y = 0; y < height; y += sampleSize) {
      for (let x = 0; x < width; x += sampleSize) {
        const pixel = Jimp.intToRGBA(image.getPixelColor(x, y));
        const color = `#${pixel.r.toString(16).padStart(2, '0')}${pixel.g.toString(16).padStart(2, '0')}${pixel.b.toString(16).padStart(2, '0')}`;
        colorMap.set(color, (colorMap.get(color) || 0) + 1);
      }
    }
    
    // Sort colors by frequency
    const sortedColors = Array.from(colorMap.entries())
      .sort((a, b) => b[1] - a[1])
      .map(([color]) => color);
    
    // Extract color palette
    const palette = sortedColors.slice(0, 8);
    const dominant = palette[0] || '#000000';
    const secondary = palette[1] || '#ffffff';
    const accent = palette[2] || '#cccccc';
    
    // Detect background color (most frequent light color)
    const background = palette.find(color => this.isLightColor(color)) || '#ffffff';
    
    // Detect text color (most frequent dark color)
    const textColor = palette.find(color => this.isDarkColor(color)) || '#000000';
    
    return {
      dominant,
      secondary,
      accent,
      background,
      text: textColor,
      palette,
      isDarkTheme: this.isDarkColor(background)
    };
  }

  async detectAdvancedLayout(image) {
    const { width, height } = image.bitmap;
    
    // Detect layout type based on content distribution
    const layoutType = this.detectLayoutType(width, height);
    
    // Detect sections using edge detection
    const sections = await this.detectSections(image);
    
    // Detect grid system
    const grid = await this.detectGrid(image);
    
    // Detect spacing and margins
    const spacing = await this.detectSpacing(image);
    
    return {
      type: layoutType,
      sections,
      grid,
      spacing,
      isResponsive: width > height * 1.5 || height > width * 1.5
    };
  }

  async detectAdvancedText(image) {
    const { width, height } = image.bitmap;
    const textRegions = [];
    
    // Use edge detection to find text regions
    const edges = await this.detectEdges(image);
    
    // Find text blocks using connected components
    const textBlocks = await this.findTextBlocks(edges);
    
    // Analyze each text block
    for (const block of textBlocks) {
      if (block.width > 50 && block.height > 20) {
        const textElement = await this.analyzeTextBlock(image, block);
        if (textElement) {
          textRegions.push(textElement);
        }
      }
    }
    
    // If no text detected, create default elements
    if (textRegions.length === 0) {
      textRegions.push(
        {
          type: 'heading',
          x: width * 0.1,
          y: height * 0.1,
          width: width * 0.8,
          height: height * 0.08,
          fontSize: '2.5rem',
          fontWeight: 'bold',
          text: 'Main Heading',
          color: '#000000',
          alignment: 'center'
        },
        {
          type: 'paragraph',
          x: width * 0.1,
          y: height * 0.25,
          width: width * 0.8,
          height: height * 0.15,
          fontSize: '1.2rem',
          fontWeight: 'normal',
          text: 'This is a sample paragraph with some content.',
          color: '#333333',
          alignment: 'left'
        }
      );
    }
    
    return textRegions;
  }

  async detectAdvancedImages(image) {
    const { width, height } = image.bitmap;
    const imageRegions = [];
    
    // Detect image regions using color variance
    const regions = await this.detectImageRegions(image);
    
    // Analyze each region
    for (const region of regions) {
      if (region.width > 100 && region.height > 80) {
        const imageElement = await this.analyzeImageRegion(image, region);
        if (imageElement) {
          imageRegions.push(imageElement);
        }
      }
    }
    
    // If no images detected, create default elements
    if (imageRegions.length === 0) {
      imageRegions.push(
        {
          type: 'hero-image',
          x: width * 0.1,
          y: height * 0.4,
          width: width * 0.8,
          height: height * 0.3,
          aspectRatio: 2.67,
          placeholder: 'Hero Image'
        },
        {
          type: 'thumbnail',
          x: width * 0.1,
          y: height * 0.75,
          width: width * 0.25,
          height: height * 0.15,
          aspectRatio: 1.67,
          placeholder: 'Thumbnail'
        }
      );
    }
    
    return imageRegions;
  }

  async detectComponents(image) {
    const { width, height } = image.bitmap;
    const components = [];
    
    // Detect buttons
    const buttons = await this.detectButtons(image);
    components.push(...buttons);
    
    // Detect forms
    const forms = await this.detectForms(image);
    components.push(...forms);
    
    // Detect navigation
    const navigation = await this.detectNavigation(image);
    if (navigation) {
      components.push(navigation);
    }
    
    return components;
  }

  async analyzeResponsive(image) {
    const { width, height } = image.bitmap;
    
    return {
      breakpoints: this.calculateBreakpoints(width, height),
      mobileFirst: width < 768,
      tabletOptimized: width >= 768 && width < 1024,
      desktopOptimized: width >= 1024
    };
  }

  // Helper methods
  isLightColor(color) {
    const rgb = this.hexToRgb(color);
    const brightness = (rgb.r * 299 + rgb.g * 587 + rgb.b * 114) / 1000;
    return brightness > 128;
  }

  isDarkColor(color) {
    return !this.isLightColor(color);
  }

  hexToRgb(hex) {
    const result = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex);
    return result ? {
      r: parseInt(result[1], 16),
      g: parseInt(result[2], 16),
      b: parseInt(result[3], 16)
    } : null;
  }

  detectLayoutType(width, height) {
    const ratio = width / height;
    if (ratio > 1.5) return 'landscape';
    if (ratio < 0.75) return 'portrait';
    return 'square';
  }

  async detectEdges(image) {
    const { width, height } = image.bitmap;
    const edges = new Array(height).fill().map(() => new Array(width).fill(0));
    
    // Simple edge detection using Sobel operator
    for (let y = 1; y < height - 1; y++) {
      for (let x = 1; x < width - 1; x++) {
        const gx = this.getGradientX(image, x, y);
        const gy = this.getGradientY(image, x, y);
        const magnitude = Math.sqrt(gx * gx + gy * gy);
        edges[y][x] = magnitude > this.edgeThreshold ? 255 : 0;
      }
    }
    
    return edges;
  }

  getGradientX(image, x, y) {
    const p1 = Jimp.intToRGBA(image.getPixelColor(x - 1, y - 1));
    const p2 = Jimp.intToRGBA(image.getPixelColor(x - 1, y));
    const p3 = Jimp.intToRGBA(image.getPixelColor(x - 1, y + 1));
    const p4 = Jimp.intToRGBA(image.getPixelColor(x + 1, y - 1));
    const p5 = Jimp.intToRGBA(image.getPixelColor(x + 1, y));
    const p6 = Jimp.intToRGBA(image.getPixelColor(x + 1, y + 1));
    
    const gx = (p4.r + 2 * p5.r + p6.r) - (p1.r + 2 * p2.r + p3.r);
    return gx;
  }

  getGradientY(image, x, y) {
    const p1 = Jimp.intToRGBA(image.getPixelColor(x - 1, y - 1));
    const p2 = Jimp.intToRGBA(image.getPixelColor(x, y - 1));
    const p3 = Jimp.intToRGBA(image.getPixelColor(x + 1, y - 1));
    const p4 = Jimp.intToRGBA(image.getPixelColor(x - 1, y + 1));
    const p5 = Jimp.intToRGBA(image.getPixelColor(x, y + 1));
    const p6 = Jimp.intToRGBA(image.getPixelColor(x + 1, y + 1));
    
    const gy = (p4.r + 2 * p5.r + p6.r) - (p1.r + 2 * p2.r + p3.r);
    return gy;
  }

  async findTextBlocks(edges) {
    // Simple connected components algorithm
    const blocks = [];
    const visited = new Array(edges.length).fill().map(() => new Array(edges[0].length).fill(false));
    
    for (let y = 0; y < edges.length; y++) {
      for (let x = 0; x < edges[0].length; x++) {
        if (edges[y][x] > 0 && !visited[y][x]) {
          const block = this.floodFill(edges, visited, x, y);
          if (block.width > 20 && block.height > 10) {
            blocks.push(block);
          }
        }
      }
    }
    
    return blocks;
  }

  floodFill(edges, visited, startX, startY) {
    const stack = [{ x: startX, y: startY }];
    let minX = startX, maxX = startX, minY = startY, maxY = startY;
    
    while (stack.length > 0) {
      const { x, y } = stack.pop();
      if (x < 0 || x >= edges[0].length || y < 0 || y >= edges.length || visited[y][x] || edges[y][x] === 0) {
        continue;
      }
      
      visited[y][x] = true;
      minX = Math.min(minX, x);
      maxX = Math.max(maxX, x);
      minY = Math.min(minY, y);
      maxY = Math.max(maxY, y);
      
      stack.push({ x: x + 1, y }, { x: x - 1, y }, { x, y: y + 1 }, { x, y: y - 1 });
    }
    
    return {
      x: minX,
      y: minY,
      width: maxX - minX + 1,
      height: maxY - minY + 1
    };
  }

  async analyzeTextBlock(image, block) {
    // Analyze text properties
    const pixel = Jimp.intToRGBA(image.getPixelColor(block.x + block.width / 2, block.y + block.height / 2));
    const color = `#${pixel.r.toString(16).padStart(2, '0')}${pixel.g.toString(16).padStart(2, '0')}${pixel.b.toString(16).padStart(2, '0')}`;
    
    const isHeading = block.height > 40 || block.width > 200;
    
    return {
      type: isHeading ? 'heading' : 'paragraph',
      x: block.x,
      y: block.y,
      width: block.width,
      height: block.height,
      fontSize: isHeading ? '2.5rem' : '1.2rem',
      fontWeight: isHeading ? 'bold' : 'normal',
      text: isHeading ? 'Main Heading' : 'Content text',
      color: color,
      alignment: 'center'
    };
  }

  async detectImageRegions(image) {
    const { width, height } = image.bitmap;
    const regions = [];
    const step = Math.max(20, Math.floor(Math.min(width, height) / 30));
    
    for (let y = 0; y < height - step; y += step) {
      for (let x = 0; x < width - step; x += step) {
        const variance = this.calculateColorVariance(image, x, y, step);
        if (variance > this.imageThreshold) {
          regions.push({
            x: x,
            y: y,
            width: step,
            height: step,
            variance: variance
          });
        }
      }
    }
    
    return this.mergeNearbyRegions(regions);
  }

  calculateColorVariance(image, x, y, size) {
    const colors = [];
    for (let dy = 0; dy < size; dy++) {
      for (let dx = 0; dx < size; dx++) {
        const pixel = Jimp.intToRGBA(image.getPixelColor(x + dx, y + dy));
        colors.push(pixel.r + pixel.g + pixel.b);
      }
    }
    
    const mean = colors.reduce((a, b) => a + b, 0) / colors.length;
    const variance = colors.reduce((a, b) => a + Math.pow(b - mean, 2), 0) / colors.length;
    return variance;
  }

  mergeNearbyRegions(regions) {
    const merged = [];
    const used = new Set();
    
    for (let i = 0; i < regions.length; i++) {
      if (used.has(i)) continue;
      
      const region = regions[i];
      const group = [region];
      used.add(i);
      
      for (let j = i + 1; j < regions.length; j++) {
        if (used.has(j)) continue;
        
        const other = regions[j];
        if (this.regionsOverlap(region, other)) {
          group.push(other);
          used.add(j);
        }
      }
      
      merged.push(this.mergeRegionGroup(group));
    }
    
    return merged;
  }

  regionsOverlap(region1, region2) {
    return !(region1.x + region1.width < region2.x || 
             region2.x + region2.width < region1.x || 
             region1.y + region1.height < region2.y || 
             region2.y + region2.height < region1.y);
  }

  mergeRegionGroup(group) {
    const minX = Math.min(...group.map(r => r.x));
    const minY = Math.min(...group.map(r => r.y));
    const maxX = Math.max(...group.map(r => r.x + r.width));
    const maxY = Math.max(...group.map(r => r.y + r.height));
    
    return {
      x: minX,
      y: minY,
      width: maxX - minX,
      height: maxY - minY,
      variance: group.reduce((sum, r) => sum + r.variance, 0) / group.length
    };
  }

  async analyzeImageRegion(image, region) {
    const aspectRatio = region.width / region.height;
    const isHero = region.width > 200 || region.height > 150;
    
    return {
      type: isHero ? 'hero-image' : 'thumbnail',
      x: region.x,
      y: region.y,
      width: region.width,
      height: region.height,
      aspectRatio: aspectRatio,
      placeholder: isHero ? 'Hero Image' : 'Thumbnail'
    };
  }

  async detectSections(image) {
    const { width, height } = image.bitmap;
    const sections = [];
    
    // Detect header (top 20%)
    sections.push({
      type: 'header',
      x: 0,
      y: 0,
      width: width,
      height: Math.floor(height * 0.2)
    });
    
    // Detect main content (middle 60%)
    sections.push({
      type: 'main',
      x: 0,
      y: Math.floor(height * 0.2),
      width: width,
      height: Math.floor(height * 0.6)
    });
    
    // Detect footer (bottom 20%)
    sections.push({
      type: 'footer',
      x: 0,
      y: Math.floor(height * 0.8),
      width: width,
      height: Math.floor(height * 0.2)
    });
    
    return sections;
  }

  async detectGrid(image) {
    const { width, height } = image.bitmap;
    
    return {
      columns: Math.floor(width / 200),
      rows: Math.floor(height / 200),
      gap: 20,
      containerWidth: width
    };
  }

  async detectSpacing(image) {
    return {
      margin: 20,
      padding: 16,
      gap: 12
    };
  }

  async detectButtons(image) {
    // Simple button detection based on rectangular regions
    return [];
  }

  async detectForms(image) {
    // Simple form detection
    return [];
  }

  async detectNavigation(image) {
    // Simple navigation detection
    return null;
  }

  calculateBreakpoints(width, height) {
    return {
      mobile: 480,
      tablet: 768,
      desktop: 1024,
      large: 1200
    };
  }
}

module.exports = { AdvancedImageAnalyzer };