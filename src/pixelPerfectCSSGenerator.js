class PixelPerfectCSSGenerator {
  constructor() {
    this.cssVariables = {};
  }

  generateCSS(analysis) {
    try {
      console.log('🎯 Generating Pixel-Perfect CSS...');
      
      const { metadata, colors, elements, layout } = analysis;
      
      let css = '';
      
      // Generate CSS variables
      css += this.generateCSSVariables(colors, metadata);
      
      // Generate base styles
      css += this.generateBaseStyles(colors, metadata);
      
      // Generate element-specific styles
      css += this.generateElementStyles(elements);
      
      // Generate utility classes
      css += this.generateUtilityClasses();
      
      console.log('✅ Pixel-perfect CSS generated successfully');
      return css;
      
    } catch (error) {
      console.error('❌ Pixel-perfect CSS generation failed:', error);
      throw error;
    }
  }

  generateCSSVariables(colors, metadata) {
    return `
/* Pixel-Perfect CSS Variables */
:root {
    /* Image Dimensions */
    --image-width: ${metadata.width}px;
    --image-height: ${metadata.height}px;
    --image-aspect-ratio: ${metadata.aspectRatio.toFixed(2)};
    
    /* Color Palette */
    --color-background: ${colors.background};
    --color-text: ${colors.text};
    --color-dominant: ${colors.dominant};
    
    /* Element Colors */
    --color-logo-bg: rgba(255, 255, 255, 0.9);
    --color-text-bg: rgba(255, 255, 255, 0.95);
    --color-image-bg: linear-gradient(135deg, #f8f9fa, #e9ecef);
    --color-button-bg: ${colors.dominant};
    
    /* Spacing */
    --spacing-xs: 2px;
    --spacing-sm: 4px;
    --spacing-md: 8px;
    --spacing-lg: 16px;
    
    /* Border Radius */
    --radius-sm: 2px;
    --radius-md: 4px;
    --radius-lg: 8px;
    
    /* Shadows */
    --shadow-sm: 0 1px 4px rgba(0, 0, 0, 0.1);
    --shadow-md: 0 2px 8px rgba(0, 0, 0, 0.1);
    --shadow-lg: 0 4px 16px rgba(0, 0, 0, 0.15);
    
    /* Transitions */
    --transition-fast: 0.2s ease;
    --transition-normal: 0.3s ease;
}
`;
  }

  generateBaseStyles(colors, metadata) {
    return `
/* Pixel-Perfect Base Styles */
* {
    box-sizing: border-box;
    margin: 0;
    padding: 0;
}

html {
    font-size: 16px;
    scroll-behavior: smooth;
}

body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
    background-color: var(--color-background);
    color: var(--color-text);
    line-height: 1.4;
    -webkit-font-smoothing: antialiased;
    -moz-osx-font-smoothing: grayscale;
}

/* Pixel-Perfect Container */
.pixel-perfect-container {
    position: relative;
    width: var(--image-width);
    height: var(--image-height);
    background-color: var(--color-background);
    margin: 20px auto;
    border: 1px solid #e0e0e0;
    border-radius: var(--radius-md);
    box-shadow: var(--shadow-lg);
    overflow: hidden;
}

/* Original Image Overlay */
.original-image-overlay {
    position: absolute;
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
    z-index: 1;
}

/* Pixel Elements Base */
.pixel-element {
    position: absolute;
    transition: all var(--transition-fast);
    user-select: none;
    -webkit-user-select: none;
    -moz-user-select: none;
    -ms-user-select: none;
}

.pixel-element:hover {
    transform: translateY(-1px);
    box-shadow: var(--shadow-lg);
}

.pixel-element:active {
    transform: translateY(0);
}
`;
  }

  generateElementStyles(elements) {
    return `
/* Logo Elements */
.logo-element {
    background-color: var(--color-logo-bg);
    border: 2px solid #007bff;
    border-radius: var(--radius-sm);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 100;
    cursor: pointer;
    box-shadow: var(--shadow-md);
}

.logo-content {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: var(--spacing-xs);
}

.logo-icon {
    font-size: 1.5rem;
    opacity: 0.8;
}

.logo-text {
    font-size: 0.75rem;
    font-weight: 600;
    color: #007bff;
    text-transform: uppercase;
    letter-spacing: 0.05em;
}

/* Text Elements */
.text-element {
    background-color: var(--color-text-bg);
    border: 1px solid rgba(0, 0, 0, 0.1);
    border-radius: var(--radius-sm);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 50;
    cursor: pointer;
    text-align: center;
    line-height: 1.2;
    padding: var(--spacing-sm);
    box-shadow: var(--shadow-sm);
    word-wrap: break-word;
    hyphens: auto;
}

.text-content {
    font-weight: 500;
    max-width: 100%;
    overflow: hidden;
    text-overflow: ellipsis;
}

/* Image Elements */
.image-element {
    background: var(--color-image-bg);
    border: 2px solid #dee2e6;
    border-radius: var(--radius-sm);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 30;
    cursor: pointer;
    overflow: hidden;
    box-shadow: var(--shadow-md);
    position: relative;
}

.image-content {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: var(--spacing-sm);
    position: relative;
    z-index: 2;
}

.image-icon {
    font-size: 2rem;
    opacity: 0.7;
}

.image-text {
    font-size: 0.875rem;
    font-weight: 600;
    color: #6c757d;
    text-align: center;
    background-color: rgba(255, 255, 255, 0.9);
    padding: var(--spacing-xs) var(--spacing-sm);
    border-radius: var(--radius-sm);
}

.image-overlay {
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background-color: rgba(0, 0, 0, 0.7);
    display: flex;
    align-items: center;
    justify-content: center;
    opacity: 0;
    transition: opacity var(--transition-normal);
    z-index: 3;
}

.image-element:hover .image-overlay {
    opacity: 1;
}

.image-button {
    background-color: #007bff;
    color: white;
    border: none;
    padding: var(--spacing-sm) var(--spacing-md);
    border-radius: var(--radius-sm);
    font-size: 0.875rem;
    font-weight: 600;
    cursor: pointer;
    transition: all var(--transition-fast);
}

.image-button:hover {
    background-color: #0056b3;
    transform: scale(1.05);
}

/* Button Elements */
.button-element {
    background-color: var(--color-button-bg);
    color: white;
    border: none;
    border-radius: var(--radius-sm);
    font-size: 0.875rem;
    font-weight: 600;
    cursor: pointer;
    z-index: 80;
    display: flex;
    align-items: center;
    justify-content: center;
    box-shadow: var(--shadow-md);
    transition: all var(--transition-fast);
    text-transform: uppercase;
    letter-spacing: 0.05em;
}

.button-element:hover {
    transform: translateY(-2px);
    box-shadow: var(--shadow-lg);
}

.button-element:active {
    transform: translateY(0);
    box-shadow: var(--shadow-md);
}

/* Element Type Indicators */
.pixel-element::before {
    content: attr(class);
    position: absolute;
    top: -20px;
    left: 0;
    font-size: 0.625rem;
    color: #6c757d;
    background-color: rgba(255, 255, 255, 0.9);
    padding: 2px 4px;
    border-radius: 2px;
    opacity: 0;
    transition: opacity var(--transition-fast);
    pointer-events: none;
    z-index: 1000;
}

.pixel-element:hover::before {
    opacity: 1;
}
`;
  }

  generateUtilityClasses() {
    return `
/* Utility Classes */
.hidden {
    display: none !important;
}

.visible {
    display: block !important;
}

.opacity-0 {
    opacity: 0;
}

.opacity-50 {
    opacity: 0.5;
}

.opacity-100 {
    opacity: 1;
}

.cursor-pointer {
    cursor: pointer;
}

.cursor-default {
    cursor: default;
}

.user-select-none {
    user-select: none;
    -webkit-user-select: none;
    -moz-user-select: none;
    -ms-user-select: none;
}

/* Responsive Utilities */
@media (max-width: 768px) {
    .pixel-perfect-container {
        width: 100%;
        max-width: 100vw;
        height: auto;
        aspect-ratio: var(--image-aspect-ratio);
        margin: 10px;
    }
    
    .pixel-element {
        transform: scale(0.8);
    }
}

@media (max-width: 480px) {
    .pixel-perfect-container {
        margin: 5px;
    }
    
    .pixel-element {
        transform: scale(0.6);
    }
    
    .logo-text,
    .image-text {
        font-size: 0.625rem;
    }
    
    .text-content {
        font-size: 0.75rem;
    }
}

/* Print Styles */
@media print {
    .pixel-perfect-container {
        width: 100%;
        height: auto;
        box-shadow: none;
        border: 1px solid #000;
    }
    
    .pixel-element {
        background: white !important;
        color: black !important;
        border: 1px solid #000 !important;
        box-shadow: none !important;
    }
    
    .original-image-overlay {
        display: none;
    }
}

/* High Contrast Mode */
@media (prefers-contrast: high) {
    .pixel-element {
        border-width: 2px;
        border-color: #000;
    }
    
    .logo-element {
        border-color: #000;
    }
    
    .text-element {
        background-color: white;
        color: black;
    }
}

/* Reduced Motion */
@media (prefers-reduced-motion: reduce) {
    .pixel-element,
    .image-overlay,
    .image-button {
        transition: none;
    }
    
    .pixel-element:hover {
        transform: none;
    }
}
`;
  }
}

module.exports = { PixelPerfectCSSGenerator };