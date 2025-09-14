const Jimp = require('jimp');

class ImageToHTMLConverter {
  constructor() {
    this.maxElements = 8; // محدود کردن تعداد elements
  }

  async convertImageToHTMLCSS(imagePath) {
    try {
      console.log('🖼️ Converting image to HTML/CSS...');
      
      const image = await Jimp.read(imagePath);
      const { width, height } = image.bitmap;
      
      console.log(`📐 Image: ${width}x${height}px`);
      
      // تحلیل عکس
      const colors = await this.extractColors(image);
      const elements = await this.findElements(image);
      
      const analysis = {
        width,
        height,
        colors,
        elements
      };
      
      // تولید HTML
      const html = this.generateHTML(analysis);
      
      // تولید CSS
      const css = this.generateCSS(analysis);
      
      console.log('✅ Conversion completed!');
      return { html, css, analysis };
      
    } catch (error) {
      console.error('❌ Conversion failed:', error);
      throw error;
    }
  }

  async extractColors(image) {
    const { width, height } = image.bitmap;
    const colorMap = new Map();
    const step = Math.max(10, Math.floor(Math.min(width, height) / 50));
    
    // نمونه‌گیری از رنگ‌ها
    for (let y = 0; y < height; y += step) {
      for (let x = 0; x < width; x += step) {
        const pixel = Jimp.intToRGBA(image.getPixelColor(x, y));
        const color = `#${pixel.r.toString(16).padStart(2, '0')}${pixel.g.toString(16).padStart(2, '0')}${pixel.b.toString(16).padStart(2, '0')}`;
        colorMap.set(color, (colorMap.get(color) || 0) + 1);
      }
    }
    
    // 5 رنگ اصلی
    const sortedColors = Array.from(colorMap.entries())
      .sort((a, b) => b[1] - a[1]);
    
    const mainColors = sortedColors.length > 0 ? 
      sortedColors.slice(0, Math.min(5, sortedColors.length)).map(([color]) => color) : 
      ['#ffffff', '#000000', '#cccccc', '#666666', '#333333'];
    
    return {
      background: mainColors[0] || '#ffffff',
      primary: mainColors[1] || '#000000',
      secondary: mainColors[2] || '#cccccc',
      accent: mainColors[3] || '#666666',
      text: mainColors[4] || '#333333',
      palette: mainColors // اضافه کردن palette
    };
  }

  async findElements(image) {
    const { width, height } = image.bitmap;
    const elements = [];
    
    console.log(`🔍 Analyzing image for elements: ${width}x${height}px`);
    
    // تقسیم عکس به مناطق مختلف - ساده و مؤثر
    const regionWidth = Math.floor(width / 3);
    const regionHeight = Math.floor(height / 3);
    
    // ایجاد 9 منطقه (3x3 grid)
    for (let row = 0; row < 3; row++) {
      for (let col = 0; col < 3; col++) {
        const x = col * regionWidth;
        const y = row * regionHeight;
        const w = Math.min(regionWidth, width - x);
        const h = Math.min(regionHeight, height - y);
        
        // تحلیل هر منطقه
        const regionAnalysis = this.analyzeRegion(image, x, y, w, h);
        
        if (regionAnalysis.hasContent) {
          elements.push({
            type: regionAnalysis.type,
            x: x,
            y: y,
            width: w,
            height: h,
            color: regionAnalysis.color,
            content: regionAnalysis.content,
            placeholder: regionAnalysis.placeholder
          });
        }
      }
    }
    
    // اگر هیچ element پیدا نشد، حداقل یک element اضافه کن
    if (elements.length === 0) {
      elements.push({
        type: 'div',
        x: 0,
        y: 0,
        width: width,
        height: height,
        color: '#f0f0f0',
        content: 'محتوای عکس',
        placeholder: ''
      });
    }
    
    console.log(`✅ Found ${elements.length} elements`);
    return elements;
  }
  
  analyzeRegion(image, x, y, width, height) {
    let totalR = 0, totalG = 0, totalB = 0, pixelCount = 0;
    let hasDarkPixels = false;
    let hasLightPixels = false;
    
    // نمونه‌گیری از منطقه
    const step = Math.max(5, Math.floor(Math.min(width, height) / 10));
    
    for (let dy = 0; dy < height; dy += step) {
      for (let dx = 0; dx < width; dx += step) {
        const pixel = Jimp.intToRGBA(image.getPixelColor(x + dx, y + dy));
        totalR += pixel.r;
        totalG += pixel.g;
        totalB += pixel.b;
        pixelCount++;
        
        // تشخیص رنگ‌های تیره و روشن
        if (pixel.r < 100 && pixel.g < 100 && pixel.b < 100) {
          hasDarkPixels = true;
        }
        if (pixel.r > 150 || pixel.g > 150 || pixel.b > 150) {
          hasLightPixels = true;
        }
      }
    }
    
    const avgR = Math.floor(totalR / pixelCount);
    const avgG = Math.floor(totalG / pixelCount);
    const avgB = Math.floor(totalB / pixelCount);
    const avgColor = `#${avgR.toString(16).padStart(2, '0')}${avgG.toString(16).padStart(2, '0')}${avgB.toString(16).padStart(2, '0')}`;
    
    // تشخیص نوع منطقه
    let type = 'div';
    let content = '';
    let placeholder = '';
    
    if (hasDarkPixels && hasLightPixels) {
      type = 'text';
      content = this.generateTextContent(elements.length);
    } else if (hasLightPixels && !hasDarkPixels) {
      type = 'image';
      placeholder = this.generateImagePlaceholder(elements.length);
    } else {
      type = 'div';
      content = 'منطقه';
    }
    
    return {
      hasContent: true,
      type: type,
      color: avgColor,
      content: content,
      placeholder: placeholder
    };
  }

  findTextArea(image, startX, startY, step) {
    const { width, height } = image.bitmap;
    let maxX = startX, maxY = startY;
    
    // گسترش افقی
    for (let x = startX; x < width; x += step) {
      const pixel = Jimp.intToRGBA(image.getPixelColor(x, startY));
      if (pixel.r < 100 && pixel.g < 100 && pixel.b < 100) {
        maxX = x;
      } else {
        break;
      }
    }
    
    // گسترش عمودی
    for (let y = startY; y < height; y += step) {
      const pixel = Jimp.intToRGBA(image.getPixelColor(startX, y));
      if (pixel.r < 100 && pixel.g < 100 && pixel.b < 100) {
        maxY = y;
      } else {
        break;
      }
    }
    
    return {
      x: startX,
      y: startY,
      width: maxX - startX + step,
      height: maxY - startY + step
    };
  }

  findImageArea(image, startX, startY, step) {
    const { width, height } = image.bitmap;
    let maxX = startX, maxY = startY;
    
    // گسترش برای پیدا کردن محدوده تصویر
    for (let x = startX; x < width; x += step) {
      const pixel = Jimp.intToRGBA(image.getPixelColor(x, startY));
      if (pixel.r > 100 || pixel.g > 100 || pixel.b > 100) {
        maxX = x;
      } else {
        break;
      }
    }
    
    for (let y = startY; y < height; y += step) {
      const pixel = Jimp.intToRGBA(image.getPixelColor(startX, y));
      if (pixel.r > 100 || pixel.g > 100 || pixel.b > 100) {
        maxY = y;
      } else {
        break;
      }
    }
    
    return {
      x: startX,
      y: startY,
      width: maxX - startX + step,
      height: maxY - startY + step
    };
  }

  generateTextContent(index) {
    const texts = [
      'عنوان اصلی',
      'زیرعنوان',
      'متن توضیحات',
      'محتوای صفحه',
      'نکته مهم',
      'اطلاعات',
      'توضیحات',
      'متن',
      'عنوان',
      'محتوای اصلی'
    ];
    return texts[index % texts.length];
  }

  generateImagePlaceholder(index) {
    const placeholders = [
      'تصویر اصلی',
      'عکس محصول',
      'تصویر گالری',
      'بنر',
      'آیکون',
      'تصویر',
      'عکس',
      'گرافیک',
      'تصویر کوچک',
      'تصویر بزرگ'
    ];
    return placeholders[index % placeholders.length];
  }

  generateHTML(analysis) {
    const { width, height, colors, elements } = analysis;
    
    return `<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>تبدیل شده از عکس</title>
    <link rel="stylesheet" href="styles.css">
</head>
<body>
    <div class="image-container" style="width: ${width}px; height: ${height}px; background-color: ${colors.background};">
        ${elements.map(element => this.generateElementHTML(element)).join('\n        ')}
        
        <!-- تصویر اصلی برای مقایسه -->
        <div class="original-image" style="position: absolute; top: 0; left: 0; width: 100%; height: 100%; background-image: url('original-image.jpg'); background-size: contain; background-repeat: no-repeat; background-position: center; opacity: 0.1; pointer-events: none;"></div>
    </div>
</body>
</html>`;
  }

  generateElementHTML(element) {
    if (element.type === 'text') {
      return `<div class="text-element" style="position: absolute; left: ${element.x}px; top: ${element.y}px; width: ${element.width}px; height: ${element.height}px; color: ${element.color}; display: flex; align-items: center; justify-content: center; background-color: rgba(255,255,255,0.9); border: 1px solid #ddd; border-radius: 4px; padding: 8px; font-size: 14px; text-align: center; font-weight: bold;">
                ${element.content}
              </div>`;
    } else if (element.type === 'image') {
      return `<div class="image-element" style="position: absolute; left: ${element.x}px; top: ${element.y}px; width: ${element.width}px; height: ${element.height}px; background: linear-gradient(135deg, #f0f0f0, #e0e0e0); border: 2px solid #ccc; border-radius: 8px; display: flex; align-items: center; justify-content: center; font-size: 12px; color: #666;">
                🖼️ ${element.placeholder}
              </div>`;
    } else if (element.type === 'div') {
      return `<div class="div-element" style="position: absolute; left: ${element.x}px; top: ${element.y}px; width: ${element.width}px; height: ${element.height}px; background-color: ${element.color}; border: 1px solid #999; border-radius: 4px; display: flex; align-items: center; justify-content: center; font-size: 12px; color: #333; font-weight: bold;">
                ${element.content}
              </div>`;
    }
    return '';
  }

  generateCSS(analysis) {
    const { width, height, colors } = analysis;
    
    return `/* CSS تولید شده از عکس */
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

.text-element {
    transition: all 0.3s ease;
    cursor: pointer;
}

.text-element:hover {
    transform: translateY(-2px);
    box-shadow: 0 4px 12px rgba(0,0,0,0.15);
}

.image-element {
    transition: all 0.3s ease;
    cursor: pointer;
}

.image-element:hover {
    transform: scale(1.02);
    box-shadow: 0 4px 12px rgba(0,0,0,0.15);
}

.div-element {
    transition: all 0.3s ease;
    cursor: pointer;
}

.div-element:hover {
    transform: scale(1.02);
    box-shadow: 0 4px 12px rgba(0,0,0,0.15);
}

.original-image {
    z-index: 1;
}

/* Responsive */
@media (max-width: 768px) {
    .image-container {
        width: 100% !important;
        height: auto !important;
        aspect-ratio: ${width / height};
    }
    
    .text-element,
    .image-element,
    .div-element {
        transform: scale(0.8);
    }
}

@media (max-width: 480px) {
    .text-element,
    .image-element,
    .div-element {
        transform: scale(0.6);
        font-size: 10px !important;
    }
}`;
  }
}

module.exports = { ImageToHTMLConverter };