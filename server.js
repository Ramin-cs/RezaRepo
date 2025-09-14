const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs-extra');
const cors = require('cors');
const { ImageToHTMLConverter } = require('./src/imageToHTMLConverter');
const { AdvancedImageConverter } = require('./src/advancedImageConverter');

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

// Initialize converters
const imageConverter = new ImageToHTMLConverter();
const advancedImageConverter = new AdvancedImageConverter();

// Routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Main conversion endpoint
app.post('/api/convert', upload.single('image'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No image file provided' });
    }

    const imagePath = req.file.path;
    const useAdvanced = req.body.advanced === 'true';
    
    console.log(`🖼️ Converting image with ${useAdvanced ? 'Advanced' : 'Basic'} mode:`, imagePath);

    // Convert image to HTML/CSS
    const result = useAdvanced ? 
      await advancedImageConverter.convertImageToHTMLCSS(imagePath) :
      await imageConverter.convertImageToHTMLCSS(imagePath);
    
    // Create output directory
    const outputDir = path.join('output', Date.now().toString());
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
      metadata: result.metadata,
      outputPath: outputDir,
      previewUrl: `/preview/${path.basename(outputDir)}`,
      mode: useAdvanced ? 'advanced' : 'basic',
      message: `Image converted to HTML/CSS successfully using ${useAdvanced ? 'Advanced AI' : 'Basic'} mode!`
    });
    
  } catch (error) {
    console.error('Error converting image:', error);
    res.status(500).json({ 
      error: 'Failed to convert image', 
      details: error.message 
    });
  }
});

// Preview endpoint
app.get('/preview/:id', (req, res) => {
  const outputDir = path.join('output', req.params.id);
  const htmlPath = path.join(outputDir, 'index.html');
  
  if (fs.existsSync(htmlPath)) {
    res.sendFile(path.resolve(htmlPath));
  } else {
    res.status(404).json({ error: 'Preview not found' });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
  console.log('📁 Upload images to convert them to HTML/CSS');
});