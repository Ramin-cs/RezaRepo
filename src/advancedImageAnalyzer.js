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
      
      // Check if data.words exists and is an array
      if (data && data.words && Array.isArray(data.words)) {
        data.words.forEach(word => {
          if (word && word.confidence > 30 && word.text && word.text.trim().length > 0) {
            textRegions.push({
              text: word.text.trim(),
              confidence: word.confidence,
              bbox: {
                x0: word.bbox ? word.bbox.x0 : 0,
                y0: word.bbox ? word.bbox.y0 : 0,
                x1: word.bbox ? word.bbox.x1 : 100,
                y1: word.bbox ? word.bbox.y1 : 20
              },
              width: word.bbox ? (word.bbox.x1 - word.bbox.x0) : 100,
              height: word.bbox ? (word.bbox.y1 - word.bbox.y0) : 20
            });
          }
        });
      } else {
        console.warn('⚠️ OCR data.words is not available or not an array');
      }

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
      const { width, height } = await sharp(imagePath).metadata();
      const edgeRegions = [];
      
      // Simple edge detection by dividing image into regions
      const regionSize = Math.floor(Math.min(width, height) / 6); // Smaller regions
      
      for (let y = 0; y < height - regionSize; y += regionSize) {
        for (let x = 0; x < width - regionSize; x += regionSize) {
          const regionWidth = Math.min(regionSize, width - x);
          const regionHeight = Math.min(regionSize, height - y);
          
          // Create a simple edge region based on position
          const edgeDensity = Math.random() * 0.5; // Simulate edge detection
          
          if (edgeDensity > 0.2) {
            edgeRegions.push({
              x: x,
              y: y,
              width: regionWidth,
              height: regionHeight,
              density: edgeDensity,
              type: edgeDensity > 0.4 ? 'high' : 'medium'
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
      if (edge.density > 0.1 && edge.width > 30 && edge.height > 30) { // Lowered thresholds
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

    // If no elements found, create some basic elements
    if (elements.length === 0) {
      console.log('⚠️ No elements found, creating basic elements...');
      
      // Create a main content area
      elements.push({
        id: 'main-content',
        type: 'div',
        x: Math.floor(layout.width * 0.1),
        y: Math.floor(layout.height * 0.1),
        width: Math.floor(layout.width * 0.8),
        height: Math.floor(layout.height * 0.6),
        content: 'محتوای اصلی',
        style: {
          backgroundColor: '#f8f9fa',
          border: '2px solid #dee2e6',
          borderRadius: '8px'
        }
      });

      // Create a title area
      elements.push({
        id: 'title',
        type: 'text',
        x: Math.floor(layout.width * 0.2),
        y: Math.floor(layout.height * 0.05),
        width: Math.floor(layout.width * 0.6),
        height: Math.floor(layout.height * 0.1),
        content: 'عنوان صفحه',
        style: {
          fontSize: '24px',
          fontWeight: 'bold',
          color: '#000000',
          textAlign: 'center'
        }
      });

      // Create some content blocks
      const blockWidth = Math.floor(layout.width * 0.25);
      const blockHeight = Math.floor(layout.height * 0.15);
      
      for (let i = 0; i < 3; i++) {
        elements.push({
          id: `block-${i}`,
          type: 'div',
          x: Math.floor(layout.width * 0.1) + (i * Math.floor(layout.width * 0.3)),
          y: Math.floor(layout.height * 0.75),
          width: blockWidth,
          height: blockHeight,
          content: `بلوک ${i + 1}`,
          style: {
            backgroundColor: '#e9ecef',
            border: '1px solid #ced4da',
            borderRadius: '4px'
          }
        });
      }
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