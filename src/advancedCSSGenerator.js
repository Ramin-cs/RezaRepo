class AdvancedCSSGenerator {
  constructor() {
    this.cssVariables = {};
    this.animations = {};
    this.breakpoints = {
      mobile: '480px',
      tablet: '768px',
      desktop: '1024px',
      large: '1200px'
    };
  }

  generateCSS(analysis) {
    try {
      console.log('🎨 Generating Advanced CSS...');
      
      const { metadata, colors, layout, text, images, components, responsive } = analysis;
      
      let css = '';
      
      // Generate CSS variables
      css += this.generateCSSVariables(colors, metadata);
      
      // Generate base styles
      css += this.generateBaseStyles(colors, metadata);
      
      // Generate responsive design
      css += this.generateResponsiveDesign(responsive, metadata);
      
      // Generate component styles
      css += this.generateComponentStyles(components, colors);
      
      // Generate animations
      css += this.generateAnimations();
      
      // Generate utility classes
      css += this.generateUtilityClasses(colors);
      
      // Generate print styles
      css += this.generatePrintStyles();
      
      console.log('✅ Advanced CSS generated successfully');
      return css;
      
    } catch (error) {
      console.error('❌ CSS generation failed:', error);
      throw error;
    }
  }

  generateCSSVariables(colors, metadata) {
    return `
/* CSS Custom Properties */
:root {
    /* Color Palette */
    --color-primary: ${colors.dominant};
    --color-secondary: ${colors.secondary};
    --color-accent: ${colors.accent};
    --color-background: ${colors.background};
    --color-text: ${colors.text};
    --color-text-light: ${this.lightenColor(colors.text, 0.3)};
    --color-text-dark: ${this.darkenColor(colors.text, 0.3)};
    
    /* Layout Variables */
    --container-width: ${metadata.width}px;
    --container-height: ${metadata.height}px;
    --aspect-ratio: ${(metadata.width / metadata.height).toFixed(2)};
    
    /* Spacing System */
    --spacing-xs: 4px;
    --spacing-sm: 8px;
    --spacing-md: 16px;
    --spacing-lg: 24px;
    --spacing-xl: 32px;
    --spacing-xxl: 48px;
    
    /* Typography */
    --font-family-primary: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    --font-family-secondary: 'Roboto', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    --font-size-xs: 0.75rem;
    --font-size-sm: 0.875rem;
    --font-size-base: 1rem;
    --font-size-lg: 1.125rem;
    --font-size-xl: 1.25rem;
    --font-size-2xl: 1.5rem;
    --font-size-3xl: 1.875rem;
    --font-size-4xl: 2.25rem;
    
    /* Border Radius */
    --radius-sm: 4px;
    --radius-md: 8px;
    --radius-lg: 12px;
    --radius-xl: 16px;
    --radius-full: 9999px;
    
    /* Shadows */
    --shadow-sm: 0 1px 2px 0 rgba(0, 0, 0, 0.05);
    --shadow-md: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
    --shadow-lg: 0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05);
    --shadow-xl: 0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04);
    
    /* Transitions */
    --transition-fast: 150ms ease-in-out;
    --transition-normal: 300ms ease-in-out;
    --transition-slow: 500ms ease-in-out;
    
    /* Z-Index Scale */
    --z-dropdown: 1000;
    --z-sticky: 1020;
    --z-fixed: 1030;
    --z-modal-backdrop: 1040;
    --z-modal: 1050;
    --z-popover: 1060;
    --z-tooltip: 1070;
}

/* Dark mode support */
@media (prefers-color-scheme: dark) {
    :root {
        --color-background: ${this.darkenColor(colors.background, 0.1)};
        --color-text: ${this.lightenColor(colors.text, 0.1)};
    }
}
`;
  }

  generateBaseStyles(colors, metadata) {
    return `
/* Reset and Base Styles */
*, *::before, *::after {
    box-sizing: border-box;
    margin: 0;
    padding: 0;
}

html {
    font-size: 16px;
    scroll-behavior: smooth;
    -webkit-text-size-adjust: 100%;
    -ms-text-size-adjust: 100%;
}

body {
    font-family: var(--font-family-primary);
    font-size: var(--font-size-base);
    line-height: 1.6;
    color: var(--color-text);
    background-color: var(--color-background);
    -webkit-font-smoothing: antialiased;
    -moz-osx-font-smoothing: grayscale;
    text-rendering: optimizeLegibility;
    overflow-x: hidden;
}

/* Main Container */
.main-container {
    position: relative;
    width: 100%;
    max-width: var(--container-width);
    margin: 0 auto;
    background-color: var(--color-background);
    border-radius: var(--radius-lg);
    box-shadow: var(--shadow-xl);
    overflow: hidden;
    min-height: var(--container-height);
}

/* Loading State */
.loading {
    opacity: 0;
    transition: opacity var(--transition-normal);
}

.loaded {
    opacity: 1;
}

/* Typography */
h1, h2, h3, h4, h5, h6 {
    font-weight: 600;
    line-height: 1.2;
    margin-bottom: var(--spacing-md);
    color: var(--color-text);
}

h1 { font-size: var(--font-size-4xl); }
h2 { font-size: var(--font-size-3xl); }
h3 { font-size: var(--font-size-2xl); }
h4 { font-size: var(--font-size-xl); }
h5 { font-size: var(--font-size-lg); }
h6 { font-size: var(--font-size-base); }

p {
    margin-bottom: var(--spacing-md);
    color: var(--color-text-light);
}

a {
    color: var(--color-primary);
    text-decoration: none;
    transition: color var(--transition-fast);
}

a:hover {
    color: var(--color-secondary);
    text-decoration: underline;
}

/* Interactive Elements */
.interactive-element {
    cursor: pointer;
    transition: all var(--transition-normal);
    will-change: transform, box-shadow;
}

.interactive-element:hover {
    transform: translateY(-2px);
    box-shadow: var(--shadow-lg);
}

.interactive-element:active {
    transform: translateY(0);
    transition: transform var(--transition-fast);
}

/* Text Elements */
.text-element {
    position: relative;
    display: flex;
    align-items: center;
    justify-content: center;
    text-align: center;
    border-radius: var(--radius-md);
    backdrop-filter: blur(10px);
    -webkit-backdrop-filter: blur(10px);
}

.text-element .text-content {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: var(--spacing-xs);
}

.text-element .text-label {
    font-size: var(--font-size-xs);
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--color-primary);
    background-color: rgba(255, 255, 255, 0.9);
    padding: 2px 6px;
    border-radius: var(--radius-sm);
}

.text-element .text-value {
    font-weight: 500;
    word-wrap: break-word;
    hyphens: auto;
}

/* Image Elements */
.image-element {
    position: relative;
    display: flex;
    align-items: center;
    justify-content: center;
    border-radius: var(--radius-lg);
    overflow: hidden;
    background: linear-gradient(135deg, var(--color-background), var(--color-accent));
}

.image-element .image-placeholder {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    width: 100%;
    height: 100%;
    position: relative;
}

.image-element .image-icon {
    font-size: 2rem;
    margin-bottom: var(--spacing-sm);
    opacity: 0.7;
}

.image-element .image-label {
    font-size: var(--font-size-sm);
    font-weight: 600;
    color: var(--color-text);
    text-align: center;
    background-color: rgba(255, 255, 255, 0.9);
    padding: var(--spacing-xs) var(--spacing-sm);
    border-radius: var(--radius-sm);
}

.image-element .image-overlay {
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
}

.image-element:hover .image-overlay {
    opacity: 1;
}

.image-element .image-button {
    background-color: var(--color-primary);
    color: white;
    border: none;
    padding: var(--spacing-sm) var(--spacing-md);
    border-radius: var(--radius-md);
    font-weight: 600;
    cursor: pointer;
    transition: all var(--transition-fast);
}

.image-element .image-button:hover {
    background-color: var(--color-secondary);
    transform: scale(1.05);
}

/* Section Styles */
.section-header {
    background: linear-gradient(135deg, var(--color-primary), var(--color-secondary));
    color: white;
}

.section-main {
    background-color: var(--color-background);
}

.section-footer {
    background: linear-gradient(135deg, var(--color-secondary), var(--color-primary));
    color: white;
}

.section-content {
    padding: var(--spacing-lg);
    height: 100%;
    display: flex;
    flex-direction: column;
    justify-content: center;
}

/* Component Styles */
.interactive-button {
    position: relative;
    overflow: hidden;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.05em;
}

.interactive-button::before {
    content: '';
    position: absolute;
    top: 0;
    left: -100%;
    width: 100%;
    height: 100%;
    background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.2), transparent);
    transition: left var(--transition-slow);
}

.interactive-button:hover::before {
    left: 100%;
}

.interactive-form {
    backdrop-filter: blur(10px);
    -webkit-backdrop-filter: blur(10px);
}

.interactive-form input {
    border: 2px solid var(--color-accent);
    border-radius: var(--radius-md);
    padding: var(--spacing-sm);
    font-size: var(--font-size-base);
    transition: border-color var(--transition-fast);
    background-color: rgba(255, 255, 255, 0.9);
}

.interactive-form input:focus {
    outline: none;
    border-color: var(--color-primary);
    box-shadow: 0 0 0 3px rgba(var(--color-primary), 0.1);
}

.interactive-nav ul {
    list-style: none;
    display: flex;
    gap: var(--spacing-lg);
    align-items: center;
}

.interactive-nav a {
    position: relative;
    padding: var(--spacing-sm) var(--spacing-md);
    border-radius: var(--radius-md);
    transition: all var(--transition-fast);
}

.interactive-nav a::after {
    content: '';
    position: absolute;
    bottom: 0;
    left: 50%;
    width: 0;
    height: 2px;
    background-color: var(--color-primary);
    transition: all var(--transition-fast);
    transform: translateX(-50%);
}

.interactive-nav a:hover::after {
    width: 100%;
}

/* Utility Classes */
.sr-only {
    position: absolute;
    width: 1px;
    height: 1px;
    padding: 0;
    margin: -1px;
    overflow: hidden;
    clip: rect(0, 0, 0, 0);
    white-space: nowrap;
    border: 0;
}

.focus-visible:focus {
    outline: 2px solid var(--color-primary);
    outline-offset: 2px;
}

/* Lazy Loading */
.lazy {
    opacity: 0;
    transition: opacity var(--transition-normal);
}

.lazy.loaded {
    opacity: 1;
}
`;
  }

  generateResponsiveDesign(responsive, metadata) {
    return `
/* Responsive Design */
@media (max-width: ${this.breakpoints.mobile}) {
    .main-container {
        max-width: 100%;
        margin: 0;
        border-radius: 0;
    }
    
    .text-element {
        font-size: var(--font-size-sm);
        padding: var(--spacing-sm);
    }
    
    .image-element {
        border-radius: var(--radius-md);
    }
    
    .interactive-nav ul {
        flex-direction: column;
        gap: var(--spacing-sm);
    }
    
    .interactive-form {
        padding: var(--spacing-md);
    }
}

@media (min-width: ${this.breakpoints.tablet}) and (max-width: ${this.breakpoints.desktop}) {
    .main-container {
        max-width: 90%;
    }
    
    .text-element {
        font-size: var(--font-size-base);
    }
    
    .image-element {
        border-radius: var(--radius-lg);
    }
}

@media (min-width: ${this.breakpoints.desktop}) {
    .main-container {
        max-width: var(--container-width);
    }
    
    .text-element {
        font-size: var(--font-size-lg);
    }
    
    .image-element {
        border-radius: var(--radius-xl);
    }
}

@media (min-width: ${this.breakpoints.large}) {
    .main-container {
        max-width: var(--container-width);
        box-shadow: var(--shadow-xl);
    }
}

/* High DPI Displays */
@media (-webkit-min-device-pixel-ratio: 2), (min-resolution: 192dpi) {
    .text-element,
    .image-element {
        border-width: 0.5px;
    }
}

/* Reduced Motion */
@media (prefers-reduced-motion: reduce) {
    *,
    *::before,
    *::after {
        animation-duration: 0.01ms !important;
        animation-iteration-count: 1 !important;
        transition-duration: 0.01ms !important;
        scroll-behavior: auto !important;
    }
}

/* High Contrast Mode */
@media (prefers-contrast: high) {
    .text-element,
    .image-element,
    .interactive-element {
        border-width: 2px;
        border-color: var(--color-text);
    }
}
`;
  }

  generateComponentStyles(components, colors) {
    return `
/* Component Specific Styles */
.generic-component {
    display: flex;
    align-items: center;
    justify-content: center;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.05em;
}

.component-label {
    background-color: var(--color-primary);
    color: white;
    padding: var(--spacing-xs) var(--spacing-sm);
    border-radius: var(--radius-sm);
    font-size: var(--font-size-xs);
}

/* Button Variants */
.button-primary {
    background: linear-gradient(135deg, var(--color-primary), var(--color-secondary));
    color: white;
}

.button-secondary {
    background-color: transparent;
    color: var(--color-primary);
    border: 2px solid var(--color-primary);
}

.button-ghost {
    background-color: transparent;
    color: var(--color-text);
    border: 1px solid var(--color-accent);
}

/* Form Variants */
.form-floating {
    position: relative;
}

.form-floating input {
    padding-top: var(--spacing-lg);
    padding-bottom: var(--spacing-sm);
}

.form-floating label {
    position: absolute;
    top: var(--spacing-sm);
    left: var(--spacing-sm);
    color: var(--color-text-light);
    transition: all var(--transition-fast);
    pointer-events: none;
}

.form-floating input:focus + label,
.form-floating input:not(:placeholder-shown) + label {
    top: var(--spacing-xs);
    font-size: var(--font-size-xs);
    color: var(--color-primary);
}

/* Navigation Variants */
.nav-horizontal ul {
    flex-direction: row;
}

.nav-vertical ul {
    flex-direction: column;
}

.nav-pills a {
    border-radius: var(--radius-full);
}

.nav-tabs a {
    border-bottom: 2px solid transparent;
    border-radius: 0;
}

.nav-tabs a.active {
    border-bottom-color: var(--color-primary);
}
`;
  }

  generateAnimations() {
    return `
/* Animations */
@keyframes fadeIn {
    from { opacity: 0; }
    to { opacity: 1; }
}

@keyframes slideInUp {
    from {
        opacity: 0;
        transform: translateY(30px);
    }
    to {
        opacity: 1;
        transform: translateY(0);
    }
}

@keyframes slideInDown {
    from {
        opacity: 0;
        transform: translateY(-30px);
    }
    to {
        opacity: 1;
        transform: translateY(0);
    }
}

@keyframes slideInLeft {
    from {
        opacity: 0;
        transform: translateX(-30px);
    }
    to {
        opacity: 1;
        transform: translateX(0);
    }
}

@keyframes slideInRight {
    from {
        opacity: 0;
        transform: translateX(30px);
    }
    to {
        opacity: 1;
        transform: translateX(0);
    }
}

@keyframes scaleIn {
    from {
        opacity: 0;
        transform: scale(0.9);
    }
    to {
        opacity: 1;
        transform: scale(1);
    }
}

@keyframes pulse {
    0%, 100% {
        transform: scale(1);
    }
    50% {
        transform: scale(1.05);
    }
}

@keyframes spin {
    from { transform: rotate(0deg); }
    to { transform: rotate(360deg); }
}

@keyframes bounce {
    0%, 20%, 53%, 80%, 100% {
        transform: translate3d(0, 0, 0);
    }
    40%, 43% {
        transform: translate3d(0, -30px, 0);
    }
    70% {
        transform: translate3d(0, -15px, 0);
    }
    90% {
        transform: translate3d(0, -4px, 0);
    }
}

/* Animation Classes */
.animate-fade-in {
    animation: fadeIn var(--transition-normal) ease-out;
}

.animate-slide-in-up {
    animation: slideInUp var(--transition-normal) ease-out;
}

.animate-slide-in-down {
    animation: slideInDown var(--transition-normal) ease-out;
}

.animate-slide-in-left {
    animation: slideInLeft var(--transition-normal) ease-out;
}

.animate-slide-in-right {
    animation: slideInRight var(--transition-normal) ease-out;
}

.animate-scale-in {
    animation: scaleIn var(--transition-normal) ease-out;
}

.animate-pulse {
    animation: pulse 2s infinite;
}

.animate-spin {
    animation: spin 1s linear infinite;
}

.animate-bounce {
    animation: bounce 1s infinite;
}

/* Staggered Animations */
.animate-stagger > * {
    animation-delay: calc(var(--stagger-delay, 0) * 100ms);
}

.animate-stagger > *:nth-child(1) { --stagger-delay: 0; }
.animate-stagger > *:nth-child(2) { --stagger-delay: 1; }
.animate-stagger > *:nth-child(3) { --stagger-delay: 2; }
.animate-stagger > *:nth-child(4) { --stagger-delay: 3; }
.animate-stagger > *:nth-child(5) { --stagger-delay: 4; }
`;
  }

  generateUtilityClasses(colors) {
    return `
/* Utility Classes */
.text-center { text-align: center; }
.text-left { text-align: left; }
.text-right { text-align: right; }

.font-light { font-weight: 300; }
.font-normal { font-weight: 400; }
.font-medium { font-weight: 500; }
.font-semibold { font-weight: 600; }
.font-bold { font-weight: 700; }
.font-extrabold { font-weight: 800; }

.text-xs { font-size: var(--font-size-xs); }
.text-sm { font-size: var(--font-size-sm); }
.text-base { font-size: var(--font-size-base); }
.text-lg { font-size: var(--font-size-lg); }
.text-xl { font-size: var(--font-size-xl); }
.text-2xl { font-size: var(--font-size-2xl); }
.text-3xl { font-size: var(--font-size-3xl); }
.text-4xl { font-size: var(--font-size-4xl); }

.text-primary { color: var(--color-primary); }
.text-secondary { color: var(--color-secondary); }
.text-accent { color: var(--color-accent); }
.text-background { color: var(--color-background); }
.text-text { color: var(--color-text); }

.bg-primary { background-color: var(--color-primary); }
.bg-secondary { background-color: var(--color-secondary); }
.bg-accent { background-color: var(--color-accent); }
.bg-background { background-color: var(--color-background); }

.border-primary { border-color: var(--color-primary); }
.border-secondary { border-color: var(--color-secondary); }
.border-accent { border-color: var(--color-accent); }

.rounded-sm { border-radius: var(--radius-sm); }
.rounded-md { border-radius: var(--radius-md); }
.rounded-lg { border-radius: var(--radius-lg); }
.rounded-xl { border-radius: var(--radius-xl); }
.rounded-full { border-radius: var(--radius-full); }

.shadow-sm { box-shadow: var(--shadow-sm); }
.shadow-md { box-shadow: var(--shadow-md); }
.shadow-lg { box-shadow: var(--shadow-lg); }
.shadow-xl { box-shadow: var(--shadow-xl); }

.p-0 { padding: 0; }
.p-1 { padding: var(--spacing-xs); }
.p-2 { padding: var(--spacing-sm); }
.p-3 { padding: var(--spacing-md); }
.p-4 { padding: var(--spacing-lg); }
.p-5 { padding: var(--spacing-xl); }
.p-6 { padding: var(--spacing-xxl); }

.m-0 { margin: 0; }
.m-1 { margin: var(--spacing-xs); }
.m-2 { margin: var(--spacing-sm); }
.m-3 { margin: var(--spacing-md); }
.m-4 { margin: var(--spacing-lg); }
.m-5 { margin: var(--spacing-xl); }
.m-6 { margin: var(--spacing-xxl); }

.flex { display: flex; }
.flex-col { flex-direction: column; }
.flex-row { flex-direction: row; }
.items-center { align-items: center; }
.items-start { align-items: flex-start; }
.items-end { align-items: flex-end; }
.justify-center { justify-content: center; }
.justify-start { justify-content: flex-start; }
.justify-end { justify-content: flex-end; }
.justify-between { justify-content: space-between; }
.justify-around { justify-content: space-around; }

.w-full { width: 100%; }
.h-full { height: 100%; }
.w-auto { width: auto; }
.h-auto { height: auto; }

.relative { position: relative; }
.absolute { position: absolute; }
.fixed { position: fixed; }
.sticky { position: sticky; }

.hidden { display: none; }
.block { display: block; }
.inline { display: inline; }
.inline-block { display: inline-block; }

.opacity-0 { opacity: 0; }
.opacity-25 { opacity: 0.25; }
.opacity-50 { opacity: 0.5; }
.opacity-75 { opacity: 0.75; }
.opacity-100 { opacity: 1; }

.transition { transition: all var(--transition-normal); }
.transition-fast { transition: all var(--transition-fast); }
.transition-slow { transition: all var(--transition-slow); }

.cursor-pointer { cursor: pointer; }
.cursor-not-allowed { cursor: not-allowed; }
.cursor-default { cursor: default; }

.select-none { user-select: none; }
.select-text { user-select: text; }
.select-all { user-select: all; }

.overflow-hidden { overflow: hidden; }
.overflow-auto { overflow: auto; }
.overflow-scroll { overflow: scroll; }

.truncate {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
}

.break-words {
    word-wrap: break-word;
    word-break: break-word;
}

.break-all {
    word-break: break-all;
}
`;
  }

  generatePrintStyles() {
    return `
/* Print Styles */
@media print {
    * {
        background: transparent !important;
        color: black !important;
        box-shadow: none !important;
        text-shadow: none !important;
    }
    
    .main-container {
        max-width: 100% !important;
        box-shadow: none !important;
        border: 1px solid #000 !important;
    }
    
    .interactive-element {
        transform: none !important;
        transition: none !important;
    }
    
    .text-element,
    .image-element {
        border: 1px solid #000 !important;
        background: white !important;
        color: black !important;
    }
    
    .image-element .image-overlay {
        display: none !important;
    }
    
    .interactive-button,
    .interactive-form,
    .interactive-nav {
        display: none !important;
    }
    
    a[href]:after {
        content: " (" attr(href) ")";
    }
    
    .no-print {
        display: none !important;
    }
}
`;
  }

  // Helper methods
  lightenColor(color, amount) {
    const rgb = this.hexToRgb(color);
    if (!rgb) return color;
    
    const r = Math.min(255, Math.floor(rgb.r + (255 - rgb.r) * amount));
    const g = Math.min(255, Math.floor(rgb.g + (255 - rgb.g) * amount));
    const b = Math.min(255, Math.floor(rgb.b + (255 - rgb.b) * amount));
    
    return `#${r.toString(16).padStart(2, '0')}${g.toString(16).padStart(2, '0')}${b.toString(16).padStart(2, '0')}`;
  }

  darkenColor(color, amount) {
    const rgb = this.hexToRgb(color);
    if (!rgb) return color;
    
    const r = Math.max(0, Math.floor(rgb.r * (1 - amount)));
    const g = Math.max(0, Math.floor(rgb.g * (1 - amount)));
    const b = Math.max(0, Math.floor(rgb.b * (1 - amount)));
    
    return `#${r.toString(16).padStart(2, '0')}${g.toString(16).padStart(2, '0')}${b.toString(16).padStart(2, '0')}`;
  }

  hexToRgb(hex) {
    const result = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex);
    return result ? {
      r: parseInt(result[1], 16),
      g: parseInt(result[2], 16),
      b: parseInt(result[3], 16)
    } : null;
  }
}

module.exports = { AdvancedCSSGenerator };