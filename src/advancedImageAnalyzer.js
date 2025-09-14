const Tesseract = require('tesseract.js');
const sharp = require('sharp');
const { createCanvas, loadImage } = require('canvas');

class AdvancedImageAnalyzer {
  constructor() {
    this.ocrWorker = null;
    this.initializeOCR();
  }

  async initializeOCR() {
    try {
      console.log('🔧 Initializing OCR...');
      this.ocrWorker = await Tesseract.createWorker('eng+fas'); // English + Persian
      await this.ocrWorker.setParameters({
        tessedit_char_whitelist: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789آابپتثجچحخدذرزژسشصضطظعغفقکگلمنوهیء',
        tessedit_pageseg_mode: '6' // Single uniform block
      });
      console.log('✅ OCR initialized successfully');
    } catch (error) {
      console.error('❌ OCR initialization failed:', error);
    }
  }

  async analyzeImage(imagePath) {
    console.log('🔍 Starting advanced image analysis...');
    
    try {
      // 1. Basic image info
      const imageInfo = await this.getImageInfo(imagePath);
      
      // 2. OCR Text Detection
      const textRegions = await this.detectText(imagePath);
      
      // 3. Edge Detection
      const edges = await this.detectEdges(imagePath);
      
      // 4. Color Analysis
      const colorPalette = await this.extractColorPalette(imagePath);
      
      // 5. Layout Detection
      const layout = await this.detectLayout(imagePath, edges);
      
      // 6. Element Classification
      const elements = await this.classifyElements(imagePath, textRegions, edges, layout);
      
      return {
        imageInfo,
        textRegions,
        edges,
        colorPalette,
        layout,
        elements,
        analysis: {
          totalElements: elements.length,
          textElements: elements.filter(e => e.type === 'text').length,
          imageElements: elements.filter(e => e.type === 'image').length,
          layoutType: layout.type,
          dominantColors: colorPalette.dominant.slice(0, 5)
        }
      };
      
    } catch (error) {
      console.error('❌ Advanced analysis failed:', error);
      throw error;
    }
  }

  async getImageInfo(imagePath) {
    const metadata = await sharp(imagePath).metadata();
    return {
      width: metadata.width,
      height: metadata.height,
      format: metadata.format,
      channels: metadata.channels,
      density: metadata.density
    };
  }

  async detectText(imagePath) {
    console.log('📝 Detecting text with OCR...');
    
    if (!this.ocrWorker) {
      console.warn('⚠️ OCR not available, skipping text detection');
      return [];
    }

    try {
      const { data } = await this.ocrWorker.recognize(imagePath);
      
      const textRegions = [];
      data.words.forEach(word => {
        if (word.confidence > 30 && word.text.trim().length > 0) {
          textRegions.push({
            text: word.text.trim(),
            confidence: word.confidence,
            bbox: {
              x0: word.bbox.x0,
              y0: word.bbox.y0,
              x1: word.bbox.x1,
              y1: word.bbox.y1
            },
            width: word.bbox.x1 - word.bbox.x0,
            height: word.bbox.y1 - word.bbox.y0
          });
        }
      });

      console.log(`✅ Found ${textRegions.length} text regions`);
      return textRegions;
      
    } catch (error) {
      console.error('❌ OCR failed:', error);
      return [];
    }
  }

  async detectEdges(imagePath) {
    console.log('🔍 Detecting edges...');
    
    try {
      // Convert to grayscale and detect edges
      const edgeBuffer = await sharp(imagePath)
        .greyscale()
        .convolve({
          width: 3,
          height: 3,
          kernel: [-1, -1, -1, -1, 8, -1, -1, -1, -1] // Edge detection kernel
        })
        .threshold(128)
        .png()
        .toBuffer();

      // Analyze edge density in different regions
      const { width, height } = await sharp(imagePath).metadata();
      const edgeRegions = [];
      
      const regionSize = Math.min(width, height) / 8;
      
      for (let y = 0; y < height; y += regionSize) {
        for (let x = 0; x < width; x += regionSize) {
          const regionWidth = Math.min(regionSize, width - x);
          const regionHeight = Math.min(regionSize, height - y);
          
          const regionBuffer = await sharp(edgeBuffer)
            .extract({ left: x, top: y, width: regionWidth, height: regionHeight })
            .raw()
            .toBuffer();
          
          // Calculate edge density
          let edgePixels = 0;
          for (let i = 0; i < regionBuffer.length; i++) {
            if (regionBuffer[i] > 128) edgePixels++;
          }
          
          const edgeDensity = edgePixels / regionBuffer.length;
          
          if (edgeDensity > 0.1) { // Threshold for significant edges
            edgeRegions.push({
              x, y, width: regionWidth, height: regionHeight,
              density: edgeDensity,
              type: edgeDensity > 0.3 ? 'high' : 'medium'
            });
          }
        }
      }

      console.log(`✅ Found ${edgeRegions.length} edge regions`);
      return edgeRegions;
      
    } catch (error) {
      console.error('❌ Edge detection failed:', error);
      return [];
    }
  }

  async extractColorPalette(imagePath) {
    console.log('🎨 Extracting color palette...');
    
    try {
      // Resize for faster processing
      const resizedBuffer = await sharp(imagePath)
        .resize(100, 100, { fit: 'inside' })
        .raw()
        .toBuffer();

      const colorMap = new Map();
      const { width, height } = await sharp(imagePath).metadata();
      
      // Sample colors
      for (let i = 0; i < resizedBuffer.length; i += 3) {
        const r = resizedBuffer[i];
        const g = resizedBuffer[i + 1];
        const b = resizedBuffer[i + 2];
        
        // Quantize colors to reduce palette size
        const quantizedR = Math.floor(r / 32) * 32;
        const quantizedG = Math.floor(g / 32) * 32;
        const quantizedB = Math.floor(b / 32) * 32;
        
        const color = `#${quantizedR.toString(16).padStart(2, '0')}${quantizedG.toString(16).padStart(2, '0')}${quantizedB.toString(16).padStart(2, '0')}`;
        colorMap.set(color, (colorMap.get(color) || 0) + 1);
      }

      const sortedColors = Array.from(colorMap.entries())
        .sort((a, b) => b[1] - a[1])
        .map(([color]) => color);

      const dominant = sortedColors.slice(0, 10);
      const background = dominant[0] || '#ffffff';
      const primary = dominant[1] || '#000000';
      const secondary = dominant[2] || '#cccccc';

      console.log(`✅ Extracted ${dominant.length} colors`);
      return {
        dominant,
        background,
        primary,
        secondary,
        palette: dominant
      };
      
    } catch (error) {
      console.error('❌ Color extraction failed:', error);
      return {
        dominant: ['#ffffff', '#000000', '#cccccc'],
        background: '#ffffff',
        primary: '#000000',
        secondary: '#cccccc',
        palette: ['#ffffff', '#000000', '#cccccc']
      };
    }
  }

  async detectLayout(imagePath, edges) {
    console.log('📐 Detecting layout...');
    
    try {
      const { width, height } = await sharp(imagePath).metadata();
      
      // Analyze edge patterns to determine layout
      const verticalEdges = edges.filter(e => e.width < e.height);
      const horizontalEdges = edges.filter(e => e.width > e.height);
      
      let layoutType = 'single-column';
      
      if (verticalEdges.length > horizontalEdges.length * 1.5) {
        layoutType = 'multi-column';
      } else if (horizontalEdges.length > verticalEdges.length * 1.5) {
        layoutType = 'horizontal-sections';
      } else if (edges.length > 10) {
        layoutType = 'grid';
      }

      // Detect header/footer areas
      const headerHeight = height * 0.15;
      const footerHeight = height * 0.15;
      
      const headerEdges = edges.filter(e => e.y < headerHeight);
      const footerEdges = edges.filter(e => e.y > height - footerHeight);

      return {
        type: layoutType,
        width,
        height,
        hasHeader: headerEdges.length > 2,
        hasFooter: footerEdges.length > 2,
        headerHeight: headerEdges.length > 2 ? headerHeight : 0,
        footerHeight: footerEdges.length > 2 ? footerHeight : 0,
        columns: layoutType === 'multi-column' ? Math.ceil(verticalEdges.length / 3) : 1
      };
      
    } catch (error) {
      console.error('❌ Layout detection failed:', error);
      return {
        type: 'single-column',
        width: 800,
        height: 600,
        hasHeader: false,
        hasFooter: false,
        headerHeight: 0,
        footerHeight: 0,
        columns: 1
      };
    }
  }

  async classifyElements(imagePath, textRegions, edges, layout) {
    console.log('🏷️ Classifying elements...');
    
    const elements = [];
    
    // Add text elements
    textRegions.forEach((text, index) => {
      elements.push({
        id: `text-${index}`,
        type: 'text',
        x: text.bbox.x0,
        y: text.bbox.y0,
        width: text.width,
        height: text.height,
        content: text.text,
        confidence: text.confidence,
        style: {
          fontSize: Math.max(12, text.height * 0.8),
          fontWeight: text.confidence > 70 ? 'bold' : 'normal',
          color: '#000000'
        }
      });
    });

    // Add image elements based on edge regions
    edges.forEach((edge, index) => {
      if (edge.density > 0.2 && edge.width > 50 && edge.height > 50) {
        // Check if this region overlaps with text
        const overlapsWithText = textRegions.some(text => 
          !(edge.x + edge.width < text.bbox.x0 || 
            edge.x > text.bbox.x1 || 
            edge.y + edge.height < text.bbox.y0 || 
            edge.y > text.bbox.y1)
        );

        if (!overlapsWithText) {
          elements.push({
            id: `image-${index}`,
            type: 'image',
            x: edge.x,
            y: edge.y,
            width: edge.width,
            height: edge.height,
            placeholder: `تصویر ${index + 1}`,
            style: {
              borderRadius: '8px',
              border: '2px solid #ddd'
            }
          });
        }
      }
    });

    // Add layout containers
    if (layout.hasHeader) {
      elements.push({
        id: 'header',
        type: 'header',
        x: 0,
        y: 0,
        width: layout.width,
        height: layout.headerHeight,
        content: 'هدر',
        style: {
          backgroundColor: '#f8f9fa',
          borderBottom: '1px solid #dee2e6'
        }
      });
    }

    if (layout.hasFooter) {
      elements.push({
        id: 'footer',
        type: 'footer',
        x: 0,
        y: layout.height - layout.footerHeight,
        width: layout.width,
        height: layout.footerHeight,
        content: 'فوتر',
        style: {
          backgroundColor: '#f8f9fa',
          borderTop: '1px solid #dee2e6'
        }
      });
    }

    console.log(`✅ Classified ${elements.length} elements`);
    return elements;
  }

  async cleanup() {
    if (this.ocrWorker) {
      await this.ocrWorker.terminate();
      console.log('🧹 OCR worker terminated');
    }
  }
}

module.exports = { AdvancedImageAnalyzer };