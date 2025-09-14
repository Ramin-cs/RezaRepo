class PixelPerfectHTMLGenerator {
  constructor() {
    this.elementCounter = 0;
  }

  generateHTML(analysis) {
    try {
      console.log('🎯 Generating Pixel-Perfect HTML...');
      
      const { metadata, colors, elements, layout } = analysis;
      
      const html = this.createPixelPerfectHTMLDocument(analysis);
      
      console.log('✅ Pixel-perfect HTML generated successfully');
      return html;
      
    } catch (error) {
      console.error('❌ Pixel-perfect HTML generation failed:', error);
      throw error;
    }
  }

  createPixelPerfectHTMLDocument(analysis) {
    const { metadata, colors, elements, layout } = analysis;
    
    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="Pixel-perfect design converted from image">
    <title>Pixel-Perfect Design</title>
    <link rel="stylesheet" href="styles.css">
    <style>
        /* Critical CSS for pixel-perfect rendering */
        body { 
            margin: 0; 
            padding: 0; 
            background-color: ${colors.background};
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        }
        .pixel-perfect-container {
            position: relative;
            width: ${metadata.width}px;
            height: ${metadata.height}px;
            background-color: ${colors.background};
            margin: 0 auto;
            overflow: hidden;
        }
    </style>
</head>
<body>
    <div class="pixel-perfect-container">
        ${this.generatePixelPerfectElements(elements, colors)}
        ${this.generateOriginalImageOverlay(metadata)}
    </div>
    
    <script>
        // Pixel-perfect interactions
        document.addEventListener('DOMContentLoaded', function() {
            // Add click handlers for interactive elements
            document.querySelectorAll('.pixel-element').forEach(element => {
                element.addEventListener('click', function() {
                    console.log('Clicked element:', this.className);
                    this.style.outline = '2px solid #007bff';
                    setTimeout(() => {
                        this.style.outline = 'none';
                    }, 1000);
                });
            });
            
            // Add hover effects
            document.querySelectorAll('.pixel-element').forEach(element => {
                element.addEventListener('mouseenter', function() {
                    this.style.opacity = '0.8';
                });
                
                element.addEventListener('mouseleave', function() {
                    this.style.opacity = '1';
                });
            });
        });
    </script>
</body>
</html>`;
  }

  generatePixelPerfectElements(elements, colors) {
    let html = '';
    
    // Sort elements by type for better organization
    const sortedElements = {
      logo: elements.filter(el => el.type === 'logo'),
      text: elements.filter(el => el.type === 'text'),
      image: elements.filter(el => el.type === 'image'),
      button: elements.filter(el => el.type === 'button')
    };
    
    // Generate logo elements first
    sortedElements.logo.forEach((element, index) => {
      html += this.generateLogoElement(element, index);
    });
    
    // Generate text elements
    sortedElements.text.forEach((element, index) => {
      html += this.generateTextElement(element, index);
    });
    
    // Generate image elements
    sortedElements.image.forEach((element, index) => {
      html += this.generateImageElement(element, index);
    });
    
    // Generate button elements
    sortedElements.button.forEach((element, index) => {
      html += this.generateButtonElement(element, index);
    });
    
    return html;
  }

  generateLogoElement(element, index) {
    return `<div class="pixel-element logo-element" 
                style="position: absolute; 
                       left: ${element.x}px; 
                       top: ${element.y}px; 
                       width: ${element.width}px; 
                       height: ${element.height}px; 
                       background-color: rgba(255,255,255,0.9);
                       border: 2px solid #007bff;
                       border-radius: 4px;
                       display: flex;
                       align-items: center;
                       justify-content: center;
                       z-index: 100;
                       cursor: pointer;
                       box-shadow: 0 2px 8px rgba(0,0,0,0.1);">
                <div class="logo-content">
                    <div class="logo-icon">🏢</div>
                    <span class="logo-text">${element.placeholder}</span>
                </div>
            </div>`;
  }

  generateTextElement(element, index) {
    return `<div class="pixel-element text-element" 
                style="position: absolute; 
                       left: ${element.x}px; 
                       top: ${element.y}px; 
                       width: ${element.width}px; 
                       height: ${element.height}px; 
                       color: ${element.color};
                       font-size: ${element.fontSize};
                       font-weight: 500;
                       display: flex;
                       align-items: center;
                       justify-content: center;
                       background-color: rgba(255,255,255,0.95);
                       border: 1px solid rgba(0,0,0,0.1);
                       border-radius: 2px;
                       z-index: 50;
                       cursor: pointer;
                       text-align: center;
                       line-height: 1.2;
                       padding: 4px;
                       box-shadow: 0 1px 4px rgba(0,0,0,0.1);">
                <span class="text-content">${element.content}</span>
            </div>`;
  }

  generateImageElement(element, index) {
    return `<div class="pixel-element image-element" 
                style="position: absolute; 
                       left: ${element.x}px; 
                       top: ${element.y}px; 
                       width: ${element.width}px; 
                       height: ${element.height}px; 
                       background: linear-gradient(135deg, #f8f9fa, #e9ecef);
                       border: 2px solid #dee2e6;
                       border-radius: 4px;
                       display: flex;
                       align-items: center;
                       justify-content: center;
                       z-index: 30;
                       cursor: pointer;
                       overflow: hidden;
                       box-shadow: 0 2px 8px rgba(0,0,0,0.1);">
                <div class="image-content">
                    <div class="image-icon">🖼️</div>
                    <span class="image-text">${element.placeholder}</span>
                    <div class="image-overlay">
                        <button class="image-button">View</button>
                    </div>
                </div>
            </div>`;
  }

  generateButtonElement(element, index) {
    return `<button class="pixel-element button-element" 
                style="position: absolute; 
                       left: ${element.x}px; 
                       top: ${element.y}px; 
                       width: ${element.width}px; 
                       height: ${element.height}px; 
                       background-color: ${element.backgroundColor};
                       color: white;
                       border: none;
                       border-radius: 4px;
                       font-size: 14px;
                       font-weight: 600;
                       cursor: pointer;
                       z-index: 80;
                       display: flex;
                       align-items: center;
                       justify-content: center;
                       box-shadow: 0 2px 8px rgba(0,0,0,0.2);
                       transition: all 0.2s ease;">
                ${element.text}
            </button>`;
  }

  generateOriginalImageOverlay(metadata) {
    return `<div class="original-image-overlay" 
                style="position: absolute; 
                       top: 0; 
                       left: 0; 
                       width: 100%; 
                       height: 100%; 
                       background-image: url('original-image.jpg'); 
                       background-size: contain; 
                       background-repeat: no-repeat; 
                       background-position: center; 
                       opacity: 0.05; 
                       pointer-events: none; 
                       z-index: 1;">
            </div>`;
  }
}

module.exports = { PixelPerfectHTMLGenerator };