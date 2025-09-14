class AdvancedHTMLGenerator {
  constructor() {
    this.semanticElements = {
      header: 'header',
      main: 'main',
      footer: 'footer',
      section: 'section',
      article: 'article',
      aside: 'aside',
      nav: 'nav'
    };
  }

  generateHTML(analysis) {
    try {
      console.log('🎨 Generating Advanced HTML...');
      
      const { metadata, colors, layout, text, images, components, responsive } = analysis;
      
      const html = this.createAdvancedHTMLDocument(analysis);
      
      console.log('✅ Advanced HTML generated successfully');
      return html;
      
    } catch (error) {
      console.error('❌ HTML generation failed:', error);
      throw error;
    }
  }

  createAdvancedHTMLDocument(analysis) {
    const { metadata, colors, layout, text, images, components, responsive } = analysis;
    
    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="Pixel-perfect design generated from image analysis">
    <meta name="author" content="AI Image to HTML Converter">
    <title>Generated Design</title>
    <link rel="stylesheet" href="styles.css">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=Roboto:wght@300;400;500;700&display=swap" rel="stylesheet">
    <style>
        /* Critical CSS for above-the-fold content */
        .loading { opacity: 0; transition: opacity 0.3s ease; }
        .loaded { opacity: 1; }
    </style>
</head>
<body class="loading" style="background-color: ${colors.background}; color: ${colors.text};">
    ${this.generateAdvancedLayout(analysis)}
    
    <script>
        // Performance optimization
        document.addEventListener('DOMContentLoaded', function() {
            document.body.classList.add('loaded');
            
            // Lazy loading for images
            const images = document.querySelectorAll('img[data-src]');
            const imageObserver = new IntersectionObserver((entries, observer) => {
                entries.forEach(entry => {
                    if (entry.isIntersecting) {
                        const img = entry.target;
                        img.src = img.dataset.src;
                        img.classList.remove('lazy');
                        observer.unobserve(img);
                    }
                });
            });
            
            images.forEach(img => imageObserver.observe(img));
            
            // Interactive elements
            this.initializeInteractivity();
        });
        
        function initializeInteractivity() {
            // Hover effects
            document.querySelectorAll('.interactive-element').forEach(element => {
                element.addEventListener('mouseenter', function() {
                    this.style.transform = 'translateY(-2px)';
                    this.style.boxShadow = '0 8px 25px rgba(0,0,0,0.15)';
                });
                
                element.addEventListener('mouseleave', function() {
                    this.style.transform = 'translateY(0)';
                    this.style.boxShadow = '0 4px 15px rgba(0,0,0,0.1)';
                });
            });
            
            // Smooth scrolling
            document.querySelectorAll('a[href^="#"]').forEach(anchor => {
                anchor.addEventListener('click', function (e) {
                    e.preventDefault();
                    const target = document.querySelector(this.getAttribute('href'));
                    if (target) {
                        target.scrollIntoView({
                            behavior: 'smooth',
                            block: 'start'
                        });
                    }
                });
            });
        }
    </script>
</body>
</html>`;
  }

  generateAdvancedLayout(analysis) {
    const { metadata, colors, layout, text, images, components, responsive } = analysis;
    
    let html = '';
    
    // Main container with responsive design
    html += `<div class="main-container" style="max-width: ${metadata.width}px; margin: 0 auto; position: relative;">`;
    
    // Generate semantic sections
    html += this.generateSemanticSections(layout, colors);
    
    // Generate text elements with proper hierarchy
    html += this.generateAdvancedTextElements(text, colors);
    
    // Generate image elements with lazy loading
    html += this.generateAdvancedImageElements(images, colors);
    
    // Generate interactive components
    html += this.generateInteractiveComponents(components, colors);
    
    // Add original image reference for comparison
    html += `<div class="original-reference" style="position: absolute; top: 0; left: 0; width: 100%; height: 100%; background-image: url('original-image.jpg'); background-size: contain; background-repeat: no-repeat; background-position: center; opacity: 0.05; pointer-events: none; z-index: 1;"></div>`;
    
    html += '</div>';
    
    return html;
  }

  generateSemanticSections(layout, colors) {
    let html = '';
    
    layout.sections.forEach((section, index) => {
      const semanticTag = this.semanticElements[section.type] || 'div';
      const sectionClass = `section-${section.type} ${section.type}`;
      
      html += `<${semanticTag} class="${sectionClass}" 
                  style="position: absolute; 
                         left: ${section.x}px; 
                         top: ${section.y}px; 
                         width: ${section.width}px; 
                         height: ${section.height}px; 
                         background-color: ${this.getSectionColor(section.type, colors)}; 
                         z-index: 10;
                         border-radius: ${this.getSectionBorderRadius(section.type)};
                         box-shadow: ${this.getSectionShadow(section.type)};">
                  <div class="section-content">
                      ${this.getSectionContent(section.type, index)}
                  </div>
              </${semanticTag}>`;
    });
    
    return html;
  }

  generateAdvancedTextElements(text, colors) {
    let html = '';
    
    text.forEach((textElement, index) => {
      const elementClass = `text-element ${textElement.type} interactive-element`;
      const textStyle = this.generateTextStyle(textElement, colors);
      
      html += `<div class="${elementClass}" 
                  style="${textStyle}">
                  <div class="text-content">
                      <span class="text-label">${textElement.type}</span>
                      <span class="text-value">${textElement.text}</span>
                  </div>
              </div>`;
    });
    
    return html;
  }

  generateAdvancedImageElements(images, colors) {
    let html = '';
    
    images.forEach((imageElement, index) => {
      const elementClass = `image-element ${imageElement.type} interactive-element`;
      const imageStyle = this.generateImageStyle(imageElement, colors);
      
      html += `<div class="${elementClass}" 
                  style="${imageStyle}">
                  <div class="image-placeholder">
                      <div class="image-icon">🖼️</div>
                      <span class="image-label">${imageElement.placeholder}</span>
                      <div class="image-overlay">
                          <button class="image-button">View Image</button>
                      </div>
                  </div>
              </div>`;
    });
    
    return html;
  }

  generateInteractiveComponents(components, colors) {
    let html = '';
    
    components.forEach((component, index) => {
      switch (component.type) {
        case 'button':
          html += this.generateButton(component, colors);
          break;
        case 'form':
          html += this.generateForm(component, colors);
          break;
        case 'navigation':
          html += this.generateNavigation(component, colors);
          break;
        default:
          html += this.generateGenericComponent(component, colors);
      }
    });
    
    return html;
  }

  generateTextStyle(textElement, colors) {
    return `position: absolute; 
            left: ${textElement.x}px; 
            top: ${textElement.y}px; 
            width: ${textElement.width}px; 
            height: ${textElement.height}px; 
            font-size: ${textElement.fontSize}; 
            font-weight: ${textElement.fontWeight}; 
            color: ${textElement.color}; 
            display: flex; 
            align-items: center; 
            justify-content: center;
            background-color: rgba(255,255,255,0.95);
            border: 2px solid ${colors.accent};
            border-radius: 8px;
            padding: 12px;
            z-index: 20;
            box-shadow: 0 4px 20px rgba(0,0,0,0.1);
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            backdrop-filter: blur(10px);
            text-align: ${textElement.alignment || 'center'};
            line-height: 1.4;`;
  }

  generateImageStyle(imageElement, colors) {
    return `position: absolute; 
            left: ${imageElement.x}px; 
            top: ${imageElement.y}px; 
            width: ${imageElement.width}px; 
            height: ${imageElement.height}px; 
            background: linear-gradient(135deg, ${colors.background}, ${colors.accent});
            border: 3px solid ${colors.dominant};
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 15;
            box-shadow: 0 8px 30px rgba(0,0,0,0.15);
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            overflow: hidden;
            position: relative;`;
  }

  generateButton(component, colors) {
    return `<button class="interactive-button interactive-element" 
                style="position: absolute; 
                       left: ${component.x}px; 
                       top: ${component.y}px; 
                       width: ${component.width}px; 
                       height: ${component.height}px; 
                       background: linear-gradient(135deg, ${colors.dominant}, ${colors.secondary});
                       color: white;
                       border: none;
                       border-radius: 8px;
                       font-size: 1rem;
                       font-weight: 600;
                       cursor: pointer;
                       z-index: 25;
                       box-shadow: 0 4px 15px rgba(0,0,0,0.2);
                       transition: all 0.3s ease;">
                ${component.text || 'Button'}
            </button>`;
  }

  generateForm(component, colors) {
    return `<form class="interactive-form interactive-element" 
                style="position: absolute; 
                       left: ${component.x}px; 
                       top: ${component.y}px; 
                       width: ${component.width}px; 
                       height: ${component.height}px; 
                       background-color: rgba(255,255,255,0.95);
                       border: 2px solid ${colors.accent};
                       border-radius: 12px;
                       padding: 20px;
                       z-index: 25;
                       box-shadow: 0 8px 25px rgba(0,0,0,0.1);">
                <input type="text" placeholder="Enter text..." 
                       style="width: 100%; padding: 12px; border: 1px solid ${colors.accent}; border-radius: 6px; margin-bottom: 10px;">
                <button type="submit" 
                        style="width: 100%; padding: 12px; background: ${colors.dominant}; color: white; border: none; border-radius: 6px; cursor: pointer;">
                    Submit
                </button>
            </form>`;
  }

  generateNavigation(component, colors) {
    return `<nav class="interactive-nav interactive-element" 
                style="position: absolute; 
                       left: ${component.x}px; 
                       top: ${component.y}px; 
                       width: ${component.width}px; 
                       height: ${component.height}px; 
                       background-color: rgba(255,255,255,0.95);
                       border: 2px solid ${colors.accent};
                       border-radius: 8px;
                       padding: 15px;
                       z-index: 25;
                       box-shadow: 0 4px 20px rgba(0,0,0,0.1);">
                <ul style="list-style: none; padding: 0; margin: 0; display: flex; gap: 20px;">
                    <li><a href="#home" style="color: ${colors.dominant}; text-decoration: none; font-weight: 500;">Home</a></li>
                    <li><a href="#about" style="color: ${colors.dominant}; text-decoration: none; font-weight: 500;">About</a></li>
                    <li><a href="#contact" style="color: ${colors.dominant}; text-decoration: none; font-weight: 500;">Contact</a></li>
                </ul>
            </nav>`;
  }

  generateGenericComponent(component, colors) {
    return `<div class="generic-component interactive-element" 
                style="position: absolute; 
                       left: ${component.x}px; 
                       top: ${component.y}px; 
                       width: ${component.width}px; 
                       height: ${component.height}px; 
                       background-color: rgba(255,255,255,0.9);
                       border: 2px solid ${colors.accent};
                       border-radius: 8px;
                       padding: 15px;
                       z-index: 20;
                       box-shadow: 0 4px 15px rgba(0,0,0,0.1);">
                <span class="component-label">${component.type}</span>
            </div>`;
  }

  getSectionColor(type, colors) {
    const colorMap = {
      'header': colors.dominant,
      'main': colors.background,
      'content': colors.background,
      'footer': colors.secondary || colors.dominant
    };
    
    return colorMap[type] || colors.background;
  }

  getSectionBorderRadius(type) {
    const radiusMap = {
      'header': '0 0 20px 20px',
      'main': '0',
      'content': '0',
      'footer': '20px 20px 0 0'
    };
    
    return radiusMap[type] || '8px';
  }

  getSectionShadow(type) {
    const shadowMap = {
      'header': '0 4px 20px rgba(0,0,0,0.1)',
      'main': 'inset 0 2px 10px rgba(0,0,0,0.05)',
      'content': 'inset 0 2px 10px rgba(0,0,0,0.05)',
      'footer': '0 -4px 20px rgba(0,0,0,0.1)'
    };
    
    return shadowMap[type] || '0 2px 10px rgba(0,0,0,0.1)';
  }

  getSectionContent(type, index) {
    const contentMap = {
      'header': `<div class="header-content">
                    <h1 class="site-title">Site Title</h1>
                    <p class="site-subtitle">Professional Design</p>
                </div>`,
      'main': `<div class="main-content">
                    <div class="content-wrapper">
                        <p>Main content area with your design elements</p>
                    </div>
                </div>`,
      'content': `<div class="content-area">
                    <div class="content-block">
                        <p>Content section with your elements</p>
                    </div>
                </div>`,
      'footer': `<div class="footer-content">
                    <p>&copy; 2024 Generated Design. All rights reserved.</p>
                </div>`
    };
    
    return contentMap[type] || `<div class="section-${type}">Section ${index + 1}</div>`;
  }
}

module.exports = { AdvancedHTMLGenerator };