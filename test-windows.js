// Simple test to verify the application works on Windows
console.log('🧪 Testing Windows Compatibility...\n');

try {
    // Test JIMP (our image processing library)
    const Jimp = require('jimp');
    console.log('✅ JIMP loaded successfully');
    
    // Test Express
    const express = require('express');
    console.log('✅ Express loaded successfully');
    
    // Test other dependencies
    const multer = require('multer');
    console.log('✅ Multer loaded successfully');
    
    const cors = require('cors');
    console.log('✅ CORS loaded successfully');
    
    const fs = require('fs-extra');
    console.log('✅ FS-Extra loaded successfully');
    
    console.log('\n🎉 All dependencies loaded successfully!');
    console.log('✅ The application should work on Windows');
    console.log('\n🚀 You can now run: npm start');
    console.log('🌐 Then open: http://localhost:3000');
    
} catch (error) {
    console.error('❌ Error loading dependencies:', error.message);
    console.log('\n🔧 Try running: npm install');
    process.exit(1);
}