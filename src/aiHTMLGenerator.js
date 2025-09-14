class AIHTMLGenerator {
  constructor() {
    this.semanticElements = {
      'header': 'header',
      'footer': 'footer',
      'navigation': 'nav',
      'main-content': 'main',
      'sidebar': 'aside',
      'article': 'article',
      'section': 'section'
    };
  }

  generateHTML(analysis) {
    console.log('🤖 Generating AI-powered HTML...');
    
    const { imageInfo, elements, layout, colorPalette } = analysis;
    
    // Generate semantic HTML structure
    const htmlStructure = this.generateSemanticStructure(elements, layout);
    
    // Generate responsive meta tags
    const metaTags = this.generateMetaTags(imageInfo);
    
    // Generate CSS variables
    const cssVariables = this.generateCSSVariables(colorPalette);
    
    const html = `<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>صفحه تبدیل شده از عکس</title>
    <link rel="stylesheet" href="styles.css">
    ${metaTags}
    <style>
        :root {
            ${cssVariables}
        }
    </style>
</head>
<body>
    ${htmlStructure}
    
    <!-- تصویر اصلی برای مقایسه -->
    <div class="original-image-overlay">
        <img src="original-image.jpg" alt="تصویر اصلی" style="opacity: 0.1; position: fixed; top: 0; left: 0; width: 100%; height: 100%; object-fit: contain; pointer-events: none; z-index: -1;">
    </div>
</body>
</html>`;

    console.log('✅ AI-powered HTML generated');
    return html;
  }

  generateSemanticStructure(elements, layout) {
    const structure = [];
    
    // Header
    if (layout.hasHeader) {
      const headerElements = elements.filter(e => e.type === 'header' || e.y < layout.headerHeight);
      structure.push(this.generateHeader(headerElements, layout));
    }
    
    // Main content
    const mainElements = elements.filter(e => 
      e.type !== 'header' && 
      e.type !== 'footer' && 
      (!layout.hasHeader || e.y >= layout.headerHeight) &&
      (!layout.hasFooter || e.y < layout.height - layout.footerHeight)
    );
    
    structure.push(this.generateMainContent(mainElements, layout));
    
    // Footer
    if (layout.hasFooter) {
      const footerElements = elements.filter(e => e.type === 'footer' || e.y >= layout.height - layout.footerHeight);
      structure.push(this.generateFooter(footerElements, layout));
    }
    
    return structure.join('\n    ');
  }

  generateHeader(elements, layout) {
    const headerElements = elements.map(e => this.generateElementHTML(e)).join('\n        ');
    
    return `<header class="page-header" style="height: ${layout.headerHeight}px;">
        <div class="header-content">
            ${headerElements}
        </div>
    </header>`;
  }

  generateMainContent(elements, layout) {
    const contentElements = elements.map(e => this.generateElementHTML(e)).join('\n        ');
    
    let layoutClass = 'single-column';
    if (layout.type === 'multi-column') {
      layoutClass = `multi-column columns-${layout.columns}`;
    } else if (layout.type === 'grid') {
      layoutClass = 'grid-layout';
    }
    
    return `<main class="main-content ${layoutClass}">
        <div class="content-wrapper">
            ${contentElements}
        </div>
    </main>`;
  }

  generateFooter(elements, layout) {
    const footerElements = elements.map(e => this.generateElementHTML(e)).join('\n        ');
    
    return `<footer class="page-footer" style="height: ${layout.footerHeight}px;">
        <div class="footer-content">
            ${footerElements}
        </div>
    </footer>`;
  }

  generateElementHTML(element) {
    const baseStyle = this.generateElementStyle(element);
    const semanticTag = this.getSemanticTag(element);
    
    if (element.type === 'text') {
      return `<${semanticTag} class="text-element" style="${baseStyle}">
            ${element.content}
        </${semanticTag}>`;
    } else if (element.type === 'image') {
      return `<${semanticTag} class="image-element" style="${baseStyle}">
            <div class="image-placeholder">
                🖼️ ${element.placeholder}
            </div>
        </${semanticTag}>`;
    } else {
      return `<${semanticTag} class="element" style="${baseStyle}">
            ${element.content || ''}
        </${semanticTag}>`;
    }
  }

  generateElementStyle(element) {
    const styles = [
      `position: absolute`,
      `left: ${element.x}px`,
      `top: ${element.y}px`,
      `width: ${element.width}px`,
      `height: ${element.height}px`
    ];
    
    if (element.style) {
      Object.entries(element.style).forEach(([prop, value]) => {
        const cssProp = prop.replace(/([A-Z])/g, '-$1').toLowerCase();
        styles.push(`${cssProp}: ${value}`);
      });
    }
    
    return styles.join('; ');
  }

  getSemanticTag(element) {
    if (element.type === 'text') {
      return element.content && element.content.length > 50 ? 'p' : 'span';
    } else if (element.type === 'image') {
      return 'figure';
    } else if (element.type === 'header') {
      return 'header';
    } else if (element.type === 'footer') {
      return 'footer';
    } else {
      return 'div';
    }
  }

  generateMetaTags(imageInfo) {
    return `
    <meta name="description" content="صفحه تبدیل شده از عکس با ابعاد ${imageInfo.width}x${imageInfo.height}">
    <meta name="generator" content="AI Image to HTML Converter">
    <meta property="og:title" content="صفحه تبدیل شده از عکس">
    <meta property="og:description" content="صفحه HTML/CSS تولید شده با هوش مصنوعی">
    <meta property="og:image" content="original-image.jpg">`;
  }

  generateCSSVariables(colorPalette) {
    return `
        --primary-color: ${colorPalette.primary};
        --secondary-color: ${colorPalette.secondary};
        --background-color: ${colorPalette.background};
        --text-color: ${this.getContrastColor(colorPalette.background)};
        --accent-color: ${colorPalette.dominant[3] || '#007bff'};
        --border-color: ${this.lightenColor(colorPalette.primary, 0.3)};
        --shadow-color: ${this.darkenColor(colorPalette.background, 0.1)};
    `;
  }

  getContrastColor(hexColor) {
    // Convert hex to RGB
    const r = parseInt(hexColor.slice(1, 3), 16);
    const g = parseInt(hexColor.slice(3, 5), 16);
    const b = parseInt(hexColor.slice(5, 7), 16);
    
    // Calculate luminance
    const luminance = (0.299 * r + 0.587 * g + 0.114 * b) / 255;
    
    return luminance > 0.5 ? '#000000' : '#ffffff';
  }

  lightenColor(hexColor, factor) {
    const r = Math.min(255, parseInt(hexColor.slice(1, 3), 16) + (255 * factor));
    const g = Math.min(255, parseInt(hexColor.slice(3, 5), 16) + (255 * factor));
    const b = Math.min(255, parseInt(hexColor.slice(5, 7), 16) + (255 * factor));
    
    return `#${r.toString(16).padStart(2, '0')}${g.toString(16).padStart(2, '0')}${b.toString(16).padStart(2, '0')}`;
  }

  darkenColor(hexColor, factor) {
    const r = Math.max(0, parseInt(hexColor.slice(1, 3), 16) - (255 * factor));
    const g = Math.max(0, parseInt(hexColor.slice(3, 5), 16) - (255 * factor));
    const b = Math.max(0, parseInt(hexColor.slice(5, 7), 16) - (255 * factor));
    
    return `#${r.toString(16).padStart(2, '0')}${g.toString(16).padStart(2, '0')}${b.toString(16).padStart(2, '0')}`;
  }
}

module.exports = { AIHTMLGenerator };