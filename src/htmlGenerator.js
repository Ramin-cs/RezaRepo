class HTMLGenerator {
  constructor() {
    this.htmlTemplate = '';
  }

  generateHTML(analysisResult) {
    const { metadata, layout, text, images, colors } = analysisResult;
    
    // Generate semantic HTML structure
    const html = this.createHTMLDocument(analysisResult);
    
    return html;
  }

  createHTMLDocument(analysis) {
    const { metadata, layout, text, images, colors } = analysis;
    
    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="Pixel-perfect design generated from image">
    <title>Generated Design</title>
    <link rel="stylesheet" href="styles.css">
</head>
<body>
    <div class="design-container">
        ${this.generatePixelPerfectLayout(analysis)}
    </div>
    
    <script>
        // Make the design interactive
        document.addEventListener('DOMContentLoaded', function() {
            // Add hover effects to elements
            document.querySelectorAll('.design-element').forEach(element => {
                element.addEventListener('mouseenter', function() {
                    this.style.transform = 'scale(1.02)';
                    this.style.transition = 'transform 0.3s ease';
                });
                
                element.addEventListener('mouseleave', function() {
                    this.style.transform = 'scale(1)';
                });
            });
        });
    </script>
</body>
</html>`;
  }

  generatePixelPerfectLayout(analysis) {
    const { metadata, layout, text, images, colors } = analysis;
    const { width, height } = metadata;
    
    let html = '';
    
    // Create the main container with exact dimensions
    html += `<div class="main-design" style="width: ${width}px; height: ${height}px; position: relative; background-color: ${colors.background};">`;
    
    // Generate sections based on layout analysis
    layout.sections.forEach((section, index) => {
      html += this.generateSection(section, colors, index);
    });
    
    // Generate text elements
    text.forEach((textElement, index) => {
      html += this.generateTextElement(textElement, index);
    });
    
    // Generate image elements
    images.forEach((imageElement, index) => {
      html += this.generateImageElement(imageElement, index);
    });
    
    // Add the original image as background for reference
    html += `<div class="original-image-reference" style="position: absolute; top: 0; left: 0; width: 100%; height: 100%; background-image: url('original-image.jpg'); background-size: contain; background-repeat: no-repeat; background-position: center; opacity: 0.1; pointer-events: none; z-index: 1;"></div>`;
    
    html += '</div>';
    
    return html;
  }

  generateSection(section, colors, index) {
    const { type, x, y, width, height } = section;
    
    return `<div class="design-element section-${type}" 
                style="position: absolute; 
                       left: ${x}px; 
                       top: ${y}px; 
                       width: ${width}px; 
                       height: ${height}px; 
                       background-color: ${this.getSectionColor(type, colors)}; 
                       border: 1px solid rgba(0,0,0,0.1);
                       z-index: 10;">
                <div class="section-label">${type}</div>
            </div>`;
  }

  generateTextElement(textElement, index) {
    const { type, x, y, width, height, text, fontSize, fontWeight, color } = textElement;
    
    return `<div class="design-element text-element ${type}" 
                style="position: absolute; 
                       left: ${x}px; 
                       top: ${y}px; 
                       width: ${width}px; 
                       height: ${height}px; 
                       font-size: ${fontSize}; 
                       font-weight: ${fontWeight}; 
                       color: ${color}; 
                       display: flex; 
                       align-items: center; 
                       justify-content: center;
                       background-color: rgba(255,255,255,0.9);
                       border: 2px solid rgba(0,0,0,0.3);
                       border-radius: 4px;
                       padding: 8px;
                       z-index: 20;
                       box-shadow: 0 2px 8px rgba(0,0,0,0.1);">
                <span style="text-align: center; line-height: 1.2;">${text}</span>
            </div>`;
  }

  generateImageElement(imageElement, index) {
    const { type, x, y, width, height } = imageElement;
    
    return `<div class="design-element image-element ${type}" 
                style="position: absolute; 
                       left: ${x}px; 
                       top: ${y}px; 
                       width: ${width}px; 
                       height: ${height}px; 
                       background-color: rgba(0,0,0,0.1);
                       border: 3px dashed rgba(0,0,0,0.4);
                       border-radius: 8px;
                       display: flex;
                       align-items: center;
                       justify-content: center;
                       z-index: 15;
                       box-shadow: 0 4px 12px rgba(0,0,0,0.15);">
                <span class="image-label" style="background-color: rgba(255,255,255,0.9); padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold;">${type}</span>
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

  generateMainContent(layout, text, images) {
    const sections = layout.sections || [];
    const paragraphs = text.filter(t => t.type === 'paragraph');
    const heroImage = images.find(img => img.type === 'hero-image');
    
    let content = '<main class="main-content" role="main">';
    
    // Hero section
    if (heroImage) {
        content += this.generateHeroSection(heroImage, text);
    }
    
    // Content sections based on layout
    sections.forEach((section, index) => {
        if (section.type === 'main' || section.type === 'content') {
            content += this.generateContentSection(section, paragraphs, images, index);
        }
    });
    
    // Grid sections if detected
    if (layout.grid) {
        content += this.generateGridSection(layout.grid, images);
    }
    
    content += '</main>';
    
    return content;
  }

  generateHeroSection(heroImage, text) {
    const heading = text.find(t => t.type === 'heading') || { text: 'Welcome to Our Site' };
    const paragraph = text.find(t => t.type === 'paragraph') || { text: 'Discover amazing content and services.' };
    
    return `<section class="hero-section" id="home">
        <div class="hero-container">
            <div class="hero-content">
                <h2 class="hero-title">${heading.text}</h2>
                <p class="hero-description">${paragraph.text}</p>
                <div class="hero-actions">
                    <button class="btn btn-primary" type="button">Get Started</button>
                    <button class="btn btn-secondary" type="button">Learn More</button>
                </div>
            </div>
            <div class="hero-image">
                <img src="original-image.jpg" alt="Hero image" class="hero-img" loading="eager">
            </div>
        </div>
    </section>`;
  }

  generateContentSection(section, paragraphs, images, index) {
    const sectionId = ['about', 'services', 'features'][index] || 'content';
    const sectionTitle = ['About Us', 'Our Services', 'Key Features'][index] || 'Content';
    
    let content = `<section class="content-section" id="${sectionId}">
        <div class="container">
            <div class="section-header">
                <h2 class="section-title">${sectionTitle}</h2>
                <p class="section-subtitle">Discover what makes us special</p>
            </div>
            <div class="section-content">`;
    
    // Add paragraphs
    paragraphs.forEach((paragraph, pIndex) => {
        if (pIndex < 3) { // Limit to 3 paragraphs per section
            content += `<div class="content-block">
                <p class="content-text">${paragraph.text}</p>
            </div>`;
        }
    });
    
    // Add image thumbnails if available
    const thumbnails = images.filter(img => img.type === 'thumbnail');
    if (thumbnails.length > 0) {
        content += '<div class="image-gallery">';
        thumbnails.forEach((thumbnail, tIndex) => {
            content += `<div class="gallery-item">
                <img src="original-image.jpg" alt="Gallery image ${tIndex + 1}" class="gallery-img" loading="lazy">
            </div>`;
        });
        content += '</div>';
    }
    
    content += `</div>
        </div>
    </section>`;
    
    return content;
  }

  generateGridSection(grid, images) {
    let content = `<section class="grid-section" id="features">
        <div class="container">
            <h2 class="section-title">Featured Content</h2>
            <div class="grid-container grid-${grid.name}">`;
    
    // Generate grid items
    const totalItems = grid.cols * grid.rows;
    for (let i = 0; i < totalItems; i++) {
        content += `<div class="grid-item">
            <div class="grid-content">
                <h3 class="grid-title">Feature ${i + 1}</h3>
                <p class="grid-description">This is a sample feature description that explains the key benefits and functionality.</p>
                <button class="btn btn-outline" type="button">Learn More</button>
            </div>
        </div>`;
    }
    
    content += `</div>
        </div>
    </section>`;
    
    return content;
  }

  generateFooter(layout, colors) {
    return `<footer class="footer" role="contentinfo">
        <div class="container">
            <div class="footer-content">
                <div class="footer-section">
                    <h3 class="footer-title">Company</h3>
                    <ul class="footer-links">
                        <li><a href="#about" class="footer-link">About Us</a></li>
                        <li><a href="#services" class="footer-link">Services</a></li>
                        <li><a href="#contact" class="footer-link">Contact</a></li>
                    </ul>
                </div>
                <div class="footer-section">
                    <h3 class="footer-title">Resources</h3>
                    <ul class="footer-links">
                        <li><a href="#" class="footer-link">Documentation</a></li>
                        <li><a href="#" class="footer-link">Support</a></li>
                        <li><a href="#" class="footer-link">Blog</a></li>
                    </ul>
                </div>
                <div class="footer-section">
                    <h3 class="footer-title">Connect</h3>
                    <ul class="footer-links">
                        <li><a href="#" class="footer-link">Twitter</a></li>
                        <li><a href="#" class="footer-link">LinkedIn</a></li>
                        <li><a href="#" class="footer-link">GitHub</a></li>
                    </ul>
                </div>
            </div>
            <div class="footer-bottom">
                <p class="footer-copyright">&copy; 2024 Generated Design. All rights reserved.</p>
            </div>
        </div>
    </footer>`;
  }
}

module.exports = { HTMLGenerator };