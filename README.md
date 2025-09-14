# Image to HTML/CSS Converter

A professional web application that converts images into responsive HTML and CSS code using AI-powered analysis.

## Features

- 🖼️ **Image Upload**: Support for JPG, PNG, GIF, and WebP formats
- 🎨 **Color Analysis**: Automatic extraction of color palettes from images
- 📱 **Responsive Design**: Generates mobile-first, responsive CSS
- 🏗️ **Layout Detection**: Intelligent analysis of image structure and layout
- 👁️ **Live Preview**: Real-time preview of generated designs
- 📱 **Device Simulation**: Preview on mobile, tablet, and desktop views
- 💾 **Code Export**: Download generated HTML and CSS files
- ♿ **Accessibility**: WCAG compliant code generation
- 🎯 **Modern Standards**: Uses CSS Grid, Flexbox, and modern web practices

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd image-to-html-css-converter
```

2. Install dependencies:
```bash
npm install
```

3. Start the server:
```bash
npm start
```

4. Open your browser and navigate to `http://localhost:3000`

## Usage

1. **Upload Image**: Drag and drop an image or click to browse files
2. **Wait for Processing**: The system will analyze your image and extract design elements
3. **Preview Results**: View the generated design in different device sizes
4. **Review Code**: Examine the generated HTML and CSS code
5. **Download**: Save the generated files to your computer

## Supported Image Formats

- JPEG/JPG
- PNG
- GIF
- WebP

## Technical Features

### Image Analysis
- Color palette extraction
- Layout structure detection
- Text region identification
- Image region detection
- Responsive breakpoint analysis

### Generated Code Features
- Semantic HTML5 structure
- Modern CSS with custom properties
- Responsive design with mobile-first approach
- CSS Grid and Flexbox layouts
- Accessibility features (ARIA labels, semantic elements)
- Cross-browser compatibility
- Print-friendly styles
- Dark mode support

### Responsive Breakpoints
- Mobile: up to 768px
- Tablet: 769px - 1024px
- Desktop: 1025px and above

## API Endpoints

- `POST /api/convert` - Upload and convert image
- `GET /preview/:id` - Preview generated design
- `GET /api/download/:id` - Download generated files

## File Structure

```
├── src/
│   ├── imageAnalyzer.js    # Image analysis logic
│   ├── htmlGenerator.js    # HTML generation
│   └── cssGenerator.js     # CSS generation
├── public/
│   ├── index.html          # Main application interface
│   ├── styles.css          # Application styles
│   └── script.js           # Frontend JavaScript
├── uploads/                # Temporary image storage
├── output/                 # Generated files
├── server.js               # Express server
└── package.json            # Dependencies
```

## Development

To run in development mode with auto-restart:

```bash
npm run dev
```

## Browser Support

- Chrome 60+
- Firefox 55+
- Safari 12+
- Edge 79+

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

MIT License - see LICENSE file for details

## Support

For issues and questions, please create an issue in the repository.

---

**Note**: This application is designed for educational and prototyping purposes. For production use, consider additional security measures and performance optimizations.