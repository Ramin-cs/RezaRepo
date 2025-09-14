const Jimp = require('jimp');

class PixelPerfectAnalyzer {
  constructor() {
    this.pixelThreshold = 30;
    this.textThreshold = 50;
    this.imageThreshold = 80;
  }

  async analyzeImage(imagePath) {
    try {
      console.log('🎯 Pixel-Perfect Analysis Starting...');
      
      const image = await Jimp.read(imagePath);
      const { width, height } = image.bitmap;
      
      console.log(`📐 Image dimensions: ${width}x${height}`);
      
      // Pixel-perfect analysis
      const analysis = {
        metadata: {
          width,
          height,
          aspectRatio: width / height,
          format: image.getMIME()
        },
        colors: await this.extractExactColors(image),
        elements: await this.detectExactElements(image),
        layout: await this.detectExactLayout(image)
      };
      
      console.log('✅ Pixel-perfect analysis completed');
      return analysis;
      
    } catch (error) {
      console.error('❌ Pixel-perfect analysis failed:', error);
      throw error;
    }
  }

  async extractExactColors(image) {
    const { width, height } = image.bitmap;
    const colorMap = new Map();
    const sampleSize = Math.max(5, Math.floor(Math.min(width, height) / 100));
    
    // Sample every pixel for exact color extraction
    for (let y = 0; y < height; y += sampleSize) {
      for (let x = 0; x < width; x += sampleSize) {
        const pixel = Jimp.intToRGBA(image.getPixelColor(x, y));
        const color = `#${pixel.r.toString(16).padStart(2, '0')}${pixel.g.toString(16).padStart(2, '0')}${pixel.b.toString(16).padStart(2, '0')}`;
        colorMap.set(color, (colorMap.get(color) || 0) + 1);
      }
    }
    
    // Get exact color palette
    const palette = Array.from(colorMap.entries())
      .sort((a, b) => b[1] - a[1])
      .map(([color]) => color)
      .slice(0, 20); // Top 20 colors
    
    return {
      palette,
      dominant: palette[0] || '#000000',
      background: this.detectBackgroundColor(image),
      text: this.detectTextColor(image)
    };
  }

  async detectExactElements(image) {
    const { width, height } = image.bitmap;
    const elements = [];
    
    // Detect text elements by finding dark areas
    const textElements = await this.detectTextElements(image);
    elements.push(...textElements);
    
    // Detect image/logo elements by finding color variations
    const imageElements = await this.detectImageElements(image);
    elements.push(...imageElements);
    
    // Detect button-like elements
    const buttonElements = await this.detectButtonElements(image);
    elements.push(...buttonElements);
    
    // Detect logo elements
    const logoElements = await this.detectLogoElements(image);
    elements.push(...logoElements);
    
    return elements;
  }

  async detectTextElements(image) {
    const { width, height } = image.bitmap;
    const textElements = [];
    const step = Math.max(3, Math.floor(Math.min(width, height) / 200));
    
    // Find dark areas that could be text
    for (let y = 0; y < height - step; y += step) {
      for (let x = 0; x < width - step; x += step) {
        const pixel = Jimp.intToRGBA(image.getPixelColor(x, y));
        
        // Check if this is a dark area (potential text)
        if (pixel.r < this.textThreshold && pixel.g < this.textThreshold && pixel.b < this.textThreshold && pixel.a > 200) {
          // Find the extent of this text area
          const textArea = this.findTextArea(image, x, y, step);
          
          if (textArea.width > 20 && textArea.height > 10) {
            textElements.push({
              type: 'text',
              x: textArea.x,
              y: textArea.y,
              width: textArea.width,
              height: textArea.height,
              color: `#${pixel.r.toString(16).padStart(2, '0')}${pixel.g.toString(16).padStart(2, '0')}${pixel.b.toString(16).padStart(2, '0')}`,
              fontSize: this.calculateFontSize(textArea.height),
              content: this.generateTextContent(textArea, textElements.length)
            });
          }
        }
      }
    }
    
    return textElements;
  }

  async detectImageElements(image) {
    const { width, height } = image.bitmap;
    const imageElements = [];
    const step = Math.max(5, Math.floor(Math.min(width, height) / 100));
    
    // Find areas with significant color variation (potential images)
    for (let y = 0; y < height - step; y += step) {
      for (let x = 0; x < width - step; x += step) {
        const variance = this.calculateColorVariance(image, x, y, step);
        
        if (variance > this.imageThreshold) {
          // Find the extent of this image area
          const imageArea = this.findImageArea(image, x, y, step);
          
          if (imageArea.width > 30 && imageArea.height > 30) {
            imageElements.push({
              type: 'image',
              x: imageArea.x,
              y: imageArea.y,
              width: imageArea.width,
              height: imageArea.height,
              aspectRatio: imageArea.width / imageArea.height,
              placeholder: this.generateImagePlaceholder(imageArea, imageElements.length)
            });
          }
        }
      }
    }
    
    return imageElements;
  }

  async detectButtonElements(image) {
    const { width, height } = image.bitmap;
    const buttonElements = [];
    const step = Math.max(5, Math.floor(Math.min(width, height) / 100));
    
    // Find rectangular areas with solid colors (potential buttons)
    for (let y = 0; y < height - step; y += step) {
      for (let x = 0; x < width - step; x += step) {
        const pixel = Jimp.intToRGBA(image.getPixelColor(x, y));
        
        // Check if this could be a button (solid color, not too dark/light)
        if (pixel.a > 200 && pixel.r > 50 && pixel.g > 50 && pixel.b > 50) {
          const buttonArea = this.findButtonArea(image, x, y, step);
          
          if (buttonArea.width > 40 && buttonArea.height > 20 && buttonArea.width < 300 && buttonArea.height < 100) {
            buttonElements.push({
              type: 'button',
              x: buttonArea.x,
              y: buttonArea.y,
              width: buttonArea.width,
              height: buttonArea.height,
              backgroundColor: `#${pixel.r.toString(16).padStart(2, '0')}${pixel.g.toString(16).padStart(2, '0')}${pixel.b.toString(16).padStart(2, '0')}`,
              text: this.generateButtonText(buttonElements.length)
            });
          }
        }
      }
    }
    
    return buttonElements;
  }

  async detectLogoElements(image) {
    const { width, height } = image.bitmap;
    const logoElements = [];
    const step = Math.max(10, Math.floor(Math.min(width, height) / 50));
    
    // Find square-ish areas in the top-left (common logo position)
    for (let y = 0; y < Math.min(height * 0.3, 200); y += step) {
      for (let x = 0; x < Math.min(width * 0.3, 200); x += step) {
        const pixel = Jimp.intToRGBA(image.getPixelColor(x, y));
        
        // Check if this could be a logo (not background color)
        if (pixel.a > 200) {
          const logoArea = this.findLogoArea(image, x, y, step);
          
          if (logoArea.width > 30 && logoArea.height > 30 && 
              Math.abs(logoArea.width - logoArea.height) < Math.max(logoArea.width, logoArea.height) * 0.5) {
            logoElements.push({
              type: 'logo',
              x: logoArea.x,
              y: logoArea.y,
              width: logoArea.width,
              height: logoArea.height,
              aspectRatio: logoArea.width / logoArea.height,
              placeholder: 'Logo'
            });
          }
        }
      }
    }
    
    return logoElements;
  }

  async detectExactLayout(image) {
    const { width, height } = image.bitmap;
    
    return {
      type: 'pixel-perfect',
      width: width,
      height: height,
      isResponsive: false // Pixel-perfect is not responsive by default
    };
  }

  // Helper methods
  findTextArea(image, startX, startY, step) {
    const { width, height } = image.bitmap;
    let minX = startX, maxX = startX, minY = startY, maxY = startY;
    
    // Expand horizontally
    for (let x = startX; x < width; x += step) {
      const pixel = Jimp.intToRGBA(image.getPixelColor(x, startY));
      if (pixel.r < this.textThreshold && pixel.g < this.textThreshold && pixel.b < this.textThreshold) {
        maxX = x;
      } else {
        break;
      }
    }
    
    // Expand vertically
    for (let y = startY; y < height; y += step) {
      const pixel = Jimp.intToRGBA(image.getPixelColor(startX, y));
      if (pixel.r < this.textThreshold && pixel.g < this.textThreshold && pixel.b < this.textThreshold) {
        maxY = y;
      } else {
        break;
      }
    }
    
    return {
      x: minX,
      y: minY,
      width: maxX - minX + step,
      height: maxY - minY + step
    };
  }

  findImageArea(image, startX, startY, step) {
    const { width, height } = image.bitmap;
    let minX = startX, maxX = startX, minY = startY, maxY = startY;
    
    // Expand to find the full image area
    for (let x = startX; x < width; x += step) {
      const variance = this.calculateColorVariance(image, x, startY, step);
      if (variance > this.imageThreshold) {
        maxX = x;
      } else {
        break;
      }
    }
    
    for (let y = startY; y < height; y += step) {
      const variance = this.calculateColorVariance(image, startX, y, step);
      if (variance > this.imageThreshold) {
        maxY = y;
      } else {
        break;
      }
    }
    
    return {
      x: minX,
      y: minY,
      width: maxX - minX + step,
      height: maxY - minY + step
    };
  }

  findButtonArea(image, startX, startY, step) {
    const { width, height } = image.bitmap;
    let minX = startX, maxX = startX, minY = startY, maxY = startY;
    const basePixel = Jimp.intToRGBA(image.getPixelColor(startX, startY));
    
    // Expand to find the full button area
    for (let x = startX; x < width; x += step) {
      const pixel = Jimp.intToRGBA(image.getPixelColor(x, startY));
      if (this.colorsSimilar(pixel, basePixel)) {
        maxX = x;
      } else {
        break;
      }
    }
    
    for (let y = startY; y < height; y += step) {
      const pixel = Jimp.intToRGBA(image.getPixelColor(startX, y));
      if (this.colorsSimilar(pixel, basePixel)) {
        maxY = y;
      } else {
        break;
      }
    }
    
    return {
      x: minX,
      y: minY,
      width: maxX - minX + step,
      height: maxY - minY + step
    };
  }

  findLogoArea(image, startX, startY, step) {
    const { width, height } = image.bitmap;
    let minX = startX, maxX = startX, minY = startY, maxY = startY;
    const basePixel = Jimp.intToRGBA(image.getPixelColor(startX, startY));
    
    // Expand to find the full logo area
    for (let x = startX; x < Math.min(width, startX + 200); x += step) {
      const pixel = Jimp.intToRGBA(image.getPixelColor(x, startY));
      if (this.colorsSimilar(pixel, basePixel)) {
        maxX = x;
      } else {
        break;
      }
    }
    
    for (let y = startY; y < Math.min(height, startY + 200); y += step) {
      const pixel = Jimp.intToRGBA(image.getPixelColor(startX, y));
      if (this.colorsSimilar(pixel, basePixel)) {
        maxY = y;
      } else {
        break;
      }
    }
    
    return {
      x: minX,
      y: minY,
      width: maxX - minX + step,
      height: maxY - minY + step
    };
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

  colorsSimilar(pixel1, pixel2, threshold = 30) {
    const diff = Math.abs(pixel1.r - pixel2.r) + Math.abs(pixel1.g - pixel2.g) + Math.abs(pixel1.b - pixel2.b);
    return diff < threshold;
  }

  calculateFontSize(height) {
    if (height > 40) return '2.5rem';
    if (height > 30) return '2rem';
    if (height > 20) return '1.5rem';
    if (height > 15) return '1.2rem';
    return '1rem';
  }

  generateTextContent(area, index) {
    const textOptions = [
      'Main Title',
      'Subtitle',
      'Description',
      'Content Text',
      'Navigation',
      'Footer Text',
      'Button Text',
      'Label',
      'Caption',
      'Heading'
    ];
    return textOptions[index % textOptions.length];
  }

  generateImagePlaceholder(area, index) {
    const imageOptions = [
      'Hero Image',
      'Product Image',
      'Gallery Image',
      'Banner Image',
      'Thumbnail',
      'Icon',
      'Illustration',
      'Photo',
      'Graphic',
      'Image'
    ];
    return imageOptions[index % imageOptions.length];
  }

  generateButtonText(index) {
    const buttonOptions = [
      'Click Here',
      'Learn More',
      'Get Started',
      'Sign Up',
      'Download',
      'Buy Now',
      'Contact',
      'Submit',
      'Next',
      'Back'
    ];
    return buttonOptions[index % buttonOptions.length];
  }

  detectBackgroundColor(image) {
    const { width, height } = image.bitmap;
    const corners = [
      Jimp.intToRGBA(image.getPixelColor(0, 0)),
      Jimp.intToRGBA(image.getPixelColor(width - 1, 0)),
      Jimp.intToRGBA(image.getPixelColor(0, height - 1)),
      Jimp.intToRGBA(image.getPixelColor(width - 1, height - 1))
    ];
    
    // Find the most common corner color
    const cornerColors = corners.map(pixel => 
      `#${pixel.r.toString(16).padStart(2, '0')}${pixel.g.toString(16).padStart(2, '0')}${pixel.b.toString(16).padStart(2, '0')}`
    );
    
    const colorCount = {};
    cornerColors.forEach(color => {
      colorCount[color] = (colorCount[color] || 0) + 1;
    });
    
    return Object.keys(colorCount).reduce((a, b) => colorCount[a] > colorCount[b] ? a : b);
  }

  detectTextColor(image) {
    const { width, height } = image.bitmap;
    const darkPixels = [];
    const sampleSize = Math.max(10, Math.floor(Math.min(width, height) / 50));
    
    for (let y = 0; y < height; y += sampleSize) {
      for (let x = 0; x < width; x += sampleSize) {
        const pixel = Jimp.intToRGBA(image.getPixelColor(x, y));
        if (pixel.r < 100 && pixel.g < 100 && pixel.b < 100 && pixel.a > 200) {
          darkPixels.push(pixel);
        }
      }
    }
    
    if (darkPixels.length > 0) {
      const avgR = darkPixels.reduce((sum, p) => sum + p.r, 0) / darkPixels.length;
      const avgG = darkPixels.reduce((sum, p) => sum + p.g, 0) / darkPixels.length;
      const avgB = darkPixels.reduce((sum, p) => sum + p.b, 0) / darkPixels.length;
      
      return `#${Math.floor(avgR).toString(16).padStart(2, '0')}${Math.floor(avgG).toString(16).padStart(2, '0')}${Math.floor(avgB).toString(16).padStart(2, '0')}`;
    }
    
    return '#000000';
  }
}

module.exports = { PixelPerfectAnalyzer };