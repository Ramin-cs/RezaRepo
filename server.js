const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs-extra');
const cors = require('cors');
// const sharp = require('sharp'); // Removed due to Windows compatibility issues
const { ImageAnalyzer } = require('./src/imageAnalyzer');
const { HTMLGenerator } = require('./src/htmlGenerator');
const { CSSGenerator } = require('./src/cssGenerator');
const { AdvancedImageAnalyzer } = require('./src/advancedImageAnalyzer');
const { AdvancedHTMLGenerator } = require('./src/advancedHTMLGenerator');
const { AdvancedCSSGenerator } = require('./src/advancedCSSGenerator');
const { PixelPerfectAnalyzer } = require('./src/pixelPerfectAnalyzer');
const { PixelPerfectHTMLGenerator } = require('./src/pixelPerfectHTMLGenerator');
const { PixelPerfectCSSGenerator } = require('./src/pixelPerfectCSSGenerator');
const { SimpleImageConverter } = require('./src/simpleImageConverter');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));
app.use('/uploads', express.static('uploads'));

// Ensure uploads directory exists
fs.ensureDirSync('uploads');

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({ 
  storage: storage,
  fileFilter: (req, file, cb) => {
    const allowedTypes = /jpeg|jpg|png|gif|webp/;
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowedTypes.test(file.mimetype);
    
    if (mimetype && extname) {
      return cb(null, true);
    } else {
      cb(new Error('Only image files are allowed!'));
    }
  },
  limits: {
    fileSize: 10 * 1024 * 1024 // 10MB limit
  }
});

// Initialize analyzers and generators
const imageAnalyzer = new ImageAnalyzer();
const htmlGenerator = new HTMLGenerator();
const cssGenerator = new CSSGenerator();

// Initialize advanced analyzers and generators
const advancedImageAnalyzer = new AdvancedImageAnalyzer();
const advancedHTMLGenerator = new AdvancedHTMLGenerator();
const advancedCSSGenerator = new AdvancedCSSGenerator();

// Initialize pixel-perfect analyzers and generators
const pixelPerfectAnalyzer = new PixelPerfectAnalyzer();
const pixelPerfectHTMLGenerator = new PixelPerfectHTMLGenerator();
const pixelPerfectCSSGenerator = new PixelPerfectCSSGenerator();

// Initialize simple image converter
const simpleImageConverter = new SimpleImageConverter();

// Routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.post('/api/convert', upload.single('image'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No image file provided' });
    }

    const imagePath = req.file.path;
    console.log('Processing image:', imagePath);

    // Use advanced analyzers and generators
    console.log('🚀 Using Advanced Image Analysis...');
    const analysisResult = await advancedImageAnalyzer.analyzeImage(imagePath);
    
    // Generate advanced HTML structure
    const htmlContent = advancedHTMLGenerator.generateHTML(analysisResult);
    
    // Generate advanced CSS styles
    const cssContent = advancedCSSGenerator.generateCSS(analysisResult);
    
    // Create output directory
    const outputDir = path.join('output', Date.now().toString());
    fs.ensureDirSync(outputDir);
    
    // Save generated files
    const htmlPath = path.join(outputDir, 'index.html');
    const cssPath = path.join(outputDir, 'styles.css');
    
    fs.writeFileSync(htmlPath, htmlContent);
    fs.writeFileSync(cssPath, cssContent);
    
    // Copy original image to output directory
    const imageOutputPath = path.join(outputDir, 'original-image' + path.extname(imagePath));
    fs.copyFileSync(imagePath, imageOutputPath);
    
    res.json({
      success: true,
      html: htmlContent,
      css: cssContent,
      analysis: analysisResult,
      outputPath: outputDir,
      previewUrl: `/preview/${path.basename(outputDir)}`
    });

  } catch (error) {
    console.error('Error processing image:', error);
    res.status(500).json({ 
      error: 'Failed to process image', 
      details: error.message 
    });
  }
});

// Advanced conversion endpoint
app.post('/api/convert-advanced', upload.single('image'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No image file provided' });
    }

    const imagePath = req.file.path;
    console.log('🚀 Processing image with Advanced Analysis:', imagePath);

    // Use advanced analyzers and generators
    const analysisResult = await advancedImageAnalyzer.analyzeImage(imagePath);
    
    // Generate advanced HTML structure
    const htmlContent = advancedHTMLGenerator.generateHTML(analysisResult);
    
    // Generate advanced CSS styles
    const cssContent = advancedCSSGenerator.generateCSS(analysisResult);
    
    // Create output directory
    const outputDir = path.join('output', 'advanced-' + Date.now().toString());
    fs.ensureDirSync(outputDir);
    
    // Save generated files
    const htmlPath = path.join(outputDir, 'index.html');
    const cssPath = path.join(outputDir, 'styles.css');
    
    fs.writeFileSync(htmlPath, htmlContent);
    fs.writeFileSync(cssPath, cssContent);
    
    // Copy original image to output directory
    const imageOutputPath = path.join(outputDir, 'original-image' + path.extname(imagePath));
    fs.copyFileSync(imagePath, imageOutputPath);
    
    res.json({
      success: true,
      html: htmlContent,
      css: cssContent,
      analysis: analysisResult,
      outputPath: outputDir,
      message: 'Advanced conversion completed successfully!'
    });
    
  } catch (error) {
    console.error('Error processing image with advanced analysis:', error);
    res.status(500).json({ error: 'Failed to process image with advanced analysis' });
  }
});

// Pixel-perfect conversion endpoint
app.post('/api/convert-pixel-perfect', upload.single('image'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No image file provided' });
    }

    const imagePath = req.file.path;
    console.log('🎯 Processing image with Pixel-Perfect Analysis:', imagePath);

    // Use pixel-perfect analyzers and generators
    const analysisResult = await pixelPerfectAnalyzer.analyzeImage(imagePath);
    
    // Generate pixel-perfect HTML structure
    const htmlContent = pixelPerfectHTMLGenerator.generateHTML(analysisResult);
    
    // Generate pixel-perfect CSS styles
    const cssContent = pixelPerfectCSSGenerator.generateCSS(analysisResult);
    
    // Create output directory
    const outputDir = path.join('output', 'pixel-perfect-' + Date.now().toString());
    fs.ensureDirSync(outputDir);
    
    // Save generated files
    const htmlPath = path.join(outputDir, 'index.html');
    const cssPath = path.join(outputDir, 'styles.css');
    
    fs.writeFileSync(htmlPath, htmlContent);
    fs.writeFileSync(cssPath, cssContent);
    
    // Copy original image to output directory
    const imageOutputPath = path.join(outputDir, 'original-image' + path.extname(imagePath));
    fs.copyFileSync(imagePath, imageOutputPath);
    
    res.json({
      success: true,
      html: htmlContent,
      css: cssContent,
      analysis: analysisResult,
      outputPath: outputDir,
      message: 'Pixel-perfect conversion completed successfully!'
    });
    
  } catch (error) {
    console.error('Error processing image with pixel-perfect analysis:', error);
    res.status(500).json({ error: 'Failed to process image with pixel-perfect analysis' });
  }
});

// Simple image to HTML/CSS converter
app.post('/api/convert-simple', upload.single('image'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No image file provided' });
    }

    const imagePath = req.file.path;
    console.log('🖼️ Converting image to HTML/CSS:', imagePath);

    // Use simple converter
    const result = await simpleImageConverter.convertImageToHTMLCSS(imagePath);
    
    // Create output directory
    const outputDir = path.join('output', 'simple-' + Date.now().toString());
    fs.ensureDirSync(outputDir);
    
    // Save generated files
    const htmlPath = path.join(outputDir, 'index.html');
    const cssPath = path.join(outputDir, 'styles.css');
    
    fs.writeFileSync(htmlPath, result.html);
    fs.writeFileSync(cssPath, result.css);
    
    // Copy original image to output directory
    const imageOutputPath = path.join(outputDir, 'original-image' + path.extname(imagePath));
    fs.copyFileSync(imagePath, imageOutputPath);
    
    res.json({
      success: true,
      html: result.html,
      css: result.css,
      analysis: result.analysis,
      outputPath: outputDir,
      message: 'Image converted to HTML/CSS successfully!'
    });
    
  } catch (error) {
    console.error('Error converting image:', error);
    res.status(500).json({ error: 'Failed to convert image' });
  }
});

app.get('/preview/:id', (req, res) => {
  const outputDir = path.join('output', req.params.id);
  const htmlPath = path.join(outputDir, 'index.html');
  
  if (fs.existsSync(htmlPath)) {
    res.sendFile(path.resolve(htmlPath));
  } else {
    res.status(404).send('Preview not found');
  }
});

app.get('/api/download/:id', (req, res) => {
  const outputDir = path.join('output', req.params.id);
  
  if (fs.existsSync(outputDir)) {
    res.download(path.join(outputDir, 'index.html'));
  } else {
    res.status(404).json({ error: 'File not found' });
  }
});

// Error handling middleware
app.use((error, req, res, next) => {
  if (error instanceof multer.MulterError) {
    if (error.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ error: 'File too large. Maximum size is 10MB.' });
    }
  }
  res.status(500).json({ error: error.message });
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  console.log('Image to HTML/CSS Converter is ready!');
});