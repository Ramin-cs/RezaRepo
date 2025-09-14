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
    <meta name="description" content="Responsive design generated from image analysis">
    <title>Generated Design</title>
    <link rel="stylesheet" href="styles.css">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
</head>
<body>
    ${this.generateHeader(layout, text, colors)}
    ${this.generateMainContent(layout, text, images)}
    ${this.generateFooter(layout, colors)}
    
    <script>
        // Responsive navigation toggle
        document.addEventListener('DOMContentLoaded', function() {
            const navToggle = document.querySelector('.nav-toggle');
            const navMenu = document.querySelector('.nav-menu');
            
            if (navToggle && navMenu) {
                navToggle.addEventListener('click', function() {
                    navMenu.classList.toggle('active');
                });
            }
            
            // Smooth scrolling for anchor links
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
        });
    </script>
</body>
</html>`;
  }

  generateHeader(layout, text, colors) {
    const heading = text.find(t => t.type === 'heading') || { text: 'Welcome' };
    const headerSection = layout.sections.find(s => s.type === 'header');
    
    return `<header class="header" role="banner" style="background-color: ${colors.background}; color: ${colors.text};">
        <nav class="navbar" role="navigation" aria-label="Main navigation">
            <div class="nav-container">
                <div class="nav-brand">
                    <h1 class="brand-title" style="color: ${colors.dominant};">${heading.text}</h1>
                </div>
                <button class="nav-toggle" aria-label="Toggle navigation menu" aria-expanded="false">
                    <span class="hamburger"></span>
                    <span class="hamburger"></span>
                    <span class="hamburger"></span>
                </button>
                <ul class="nav-menu" role="menubar">
                    <li class="nav-item" role="none">
                        <a href="#home" class="nav-link" role="menuitem" style="color: ${colors.text};">Home</a>
                    </li>
                    <li class="nav-item" role="none">
                        <a href="#about" class="nav-link" role="menuitem" style="color: ${colors.text};">About</a>
                    </li>
                    <li class="nav-item" role="none">
                        <a href="#services" class="nav-link" role="menuitem" style="color: ${colors.text};">Services</a>
                    </li>
                    <li class="nav-item" role="none">
                        <a href="#contact" class="nav-link" role="menuitem" style="color: ${colors.text};">Contact</a>
                    </li>
                </ul>
            </div>
        </nav>
    </header>`;
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