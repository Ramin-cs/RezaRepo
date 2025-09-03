#!/usr/bin/env python3
"""
Enterprise Router Analyzer Build Script
Cross-platform packaging and deployment tool
"""

import os
import sys
import platform
import subprocess
import shutil
from pathlib import Path

class EnterpriseBuildTool:
    """Professional build and packaging tool"""
    
    def __init__(self):
        self.platform = platform.system().lower()
        self.arch = platform.machine()
        self.python_version = f"{sys.version_info.major}.{sys.version_info.minor}"
        
    def check_dependencies(self):
        """Check and install required dependencies"""
        required_packages = [
            'cryptography>=41.0.0',
            'pycryptodome>=3.18.0',
            'pyinstaller>=5.0.0'
        ]
        
        print("🔍 Checking dependencies...")
        
        for package in required_packages:
            try:
                subprocess.check_call([
                    sys.executable, '-m', 'pip', 'install', package, '--quiet'
                ])
                print(f"✅ {package.split('>=')[0]}")
            except subprocess.CalledProcessError as e:
                print(f"❌ Failed to install {package}: {e}")
                return False
        
        return True
    
    def create_spec_file(self):
        """Create PyInstaller spec file for enterprise build"""
        spec_content = f"""# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

a = Analysis(
    ['enterprise_router_analyzer.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('README.md', '.'),
        ('requirements.txt', '.'),
    ],
    hiddenimports=[
        'tkinter',
        'tkinter.ttk',
        'tkinter.filedialog',
        'tkinter.messagebox',
        'tkinter.scrolledtext',
        'cryptography',
        'Crypto',
        'paramiko'
    ],
    hookspath=[],
    hooksconfig={{}},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='EnterpriseRouterAnalyzer',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='router_icon.ico' if os.path.exists('router_icon.ico') else None,
)

# Create distribution folder
coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='EnterpriseRouterAnalyzer'
)
"""
        
        with open('enterprise_analyzer.spec', 'w') as f:
            f.write(spec_content)
        
        print("✅ PyInstaller spec file created")
    
    def build_executable(self):
        """Build cross-platform executable"""
        print(f"🔨 Building executable for {self.platform.title()} {self.arch}...")
        
        try:
            # Clean previous builds
            if os.path.exists('build'):
                shutil.rmtree('build')
            if os.path.exists('dist'):
                shutil.rmtree('dist')
            
            # Build with PyInstaller
            cmd = [
                sys.executable, '-m', 'PyInstaller',
                '--onefile',
                '--name', f'EnterpriseRouterAnalyzer_{self.platform}_{self.arch}',
                '--distpath', 'dist',
                '--workpath', 'build',
                '--clean',
                'enterprise_router_analyzer.py'
            ]
            
            # Add platform-specific options
            if self.platform == 'windows':
                cmd.extend(['--console', '--icon=router_icon.ico'])
            elif self.platform == 'darwin':  # macOS
                cmd.extend(['--console'])
            else:  # Linux
                cmd.extend(['--console'])
            
            subprocess.check_call(cmd)
            
            print("✅ Executable built successfully!")
            
            # List created files
            dist_path = Path('dist')
            if dist_path.exists():
                print("\n📦 Created files:")
                for file in dist_path.iterdir():
                    print(f"   • {file.name} ({file.stat().st_size // 1024} KB)")
            
            return True
            
        except subprocess.CalledProcessError as e:
            print(f"❌ Build failed: {e}")
            return False
    
    def create_deployment_package(self):
        """Create complete deployment package"""
        package_name = f"EnterpriseRouterAnalyzer_v3.0_{self.platform}_{self.arch}"
        package_dir = Path(package_name)
        
        # Create package directory
        if package_dir.exists():
            shutil.rmtree(package_dir)
        package_dir.mkdir()
        
        print(f"📦 Creating deployment package: {package_name}")
        
        # Copy executable
        dist_path = Path('dist')
        if dist_path.exists():
            for exe_file in dist_path.glob('*'):
                shutil.copy2(exe_file, package_dir)
                print(f"✅ Copied: {exe_file.name}")
        
        # Copy documentation
        docs_to_copy = [
            'README.md',
            'requirements.txt',
            'enterprise_router_analyzer.py'
        ]
        
        for doc in docs_to_copy:
            if os.path.exists(doc):
                shutil.copy2(doc, package_dir)
                print(f"✅ Copied: {doc}")
        
        # Create sample configurations
        samples_dir = package_dir / 'samples'
        samples_dir.mkdir()
        
        sample_files = [
            'cisco_enterprise.cfg',
            'tplink_archer.cfg', 
            'dlink_dir825.xml',
            'cisco_base64.cfg'
        ]
        
        for sample in sample_files:
            if os.path.exists(sample):
                shutil.copy2(sample, samples_dir)
        
        # Create deployment instructions
        instructions = f"""Enterprise Router Configuration Analyzer v3.0
Deployment Instructions

SYSTEM REQUIREMENTS:
- Operating System: {platform.system()} {platform.release()}
- Architecture: {self.arch}
- Python: {self.python_version}+ (for source code)

QUICK START:
1. Run the executable directly:
   ./{[f for f in os.listdir(package_dir) if f.startswith('EnterpriseRouterAnalyzer')][0] if any(f.startswith('EnterpriseRouterAnalyzer') for f in os.listdir(package_dir)) else 'EnterpriseRouterAnalyzer'}

2. For GUI interface:
   ./{[f for f in os.listdir(package_dir) if f.startswith('EnterpriseRouterAnalyzer')][0] if any(f.startswith('EnterpriseRouterAnalyzer') for f in os.listdir(package_dir)) else 'EnterpriseRouterAnalyzer'} --gui

3. Analyze configuration:
   ./{[f for f in os.listdir(package_dir) if f.startswith('EnterpriseRouterAnalyzer')][0] if any(f.startswith('EnterpriseRouterAnalyzer') for f in os.listdir(package_dir)) else 'EnterpriseRouterAnalyzer'} config.cfg --report report.txt

SAMPLE FILES:
Test the tool with provided sample configurations in the 'samples' folder.

PROFESSIONAL USE:
This tool is designed for network security professionals and contractors.
Generate POC reports for client presentations using the --report option.

SUPPORT:
For technical support, refer to README.md or the source code documentation.
"""
        
        with open(package_dir / 'DEPLOYMENT.txt', 'w') as f:
            f.write(instructions)
        
        print(f"✅ Deployment package created: {package_name}")
        print(f"📁 Package location: {package_dir.absolute()}")
        
        return package_dir
    
    def run_tests(self):
        """Run comprehensive tests"""
        print("🧪 Running enterprise tests...")
        
        test_files = [
            'cisco_enterprise.cfg',
            'tplink_archer.cfg',
            'dlink_dir825.xml'
        ]
        
        analyzer = EnterpriseRouterAnalyzer()
        
        for test_file in test_files:
            if os.path.exists(test_file):
                print(f"\n🔍 Testing: {test_file}")
                try:
                    result = analyzer.analyze_configuration(test_file)
                    if result['success']:
                        print(f"✅ {result['brand'].upper()} - {len(result.get('credentials', []))} credentials found")
                    else:
                        print(f"❌ Failed: {result.get('error', 'Unknown')}")
                except Exception as e:
                    print(f"❌ Error: {e}")
        
        print("\n✅ Testing completed!")


def main():
    """Build script main function"""
    builder = EnterpriseBuildTool()
    
    print("🏗️ Enterprise Router Analyzer Build Tool")
    print("=" * 60)
    print(f"Platform: {platform.system()} {platform.release()}")
    print(f"Architecture: {platform.machine()}")
    print(f"Python: {sys.version.split()[0]}")
    print("")
    
    # Check dependencies
    if not builder.check_dependencies():
        print("❌ Dependency check failed. Please install required packages manually.")
        return
    
    print("\n🏭 Creating enterprise samples...")
    create_enterprise_samples()
    
    print("\n🧪 Running tests...")
    builder.run_tests()
    
    print("\n🔨 Building executable...")
    if builder.build_executable():
        print("\n📦 Creating deployment package...")
        package_dir = builder.create_deployment_package()
        
        print(f"\n🎉 Enterprise build completed successfully!")
        print(f"📁 Package ready: {package_dir}")
        print("\nDeployment package includes:")
        print("  • Cross-platform executable")
        print("  • Sample configuration files")
        print("  • Documentation and user guide")
        print("  • Deployment instructions")
        
    else:
        print("❌ Build failed. Please check error messages above.")


if __name__ == "__main__":
    main()