#!/usr/bin/env python3
"""
Cross-Platform Manager for ARAT
Handles platform-specific paths and tool detection
"""

import os
import platform
import subprocess
from typing import List, Dict, Any, Optional

class PlatformManager:
    """Cross-platform compatibility manager"""
    
    def __init__(self):
        self.system = platform.system().lower()
        self.paths = self._get_platform_paths()
        self._setup_environment()
    
    def _get_platform_paths(self) -> Dict[str, List[str]]:
        """Get platform-specific paths for external tools"""
        paths = {
            'go_tools': [],
            'python_tools': [],
            'system_tools': []
        }
        
        if self.system == 'windows':
            # Windows paths
            paths['go_tools'] = [
                os.path.join(os.environ.get('USERPROFILE', ''), 'go', 'bin'),
                os.path.join(os.environ.get('LOCALAPPDATA', ''), 'go', 'bin'),
                'C:\\go\\bin',
                'C:\\Program Files\\Go\\bin'
            ]
            paths['python_tools'] = [
                os.path.join(os.environ.get('USERPROFILE', ''), '.local', 'bin'),
                os.path.join(os.environ.get('APPDATA', ''), 'Python', 'Scripts'),
                os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Programs', 'Python', 'Scripts')
            ]
            paths['system_tools'] = [
                'C:\\Program Files\\Git\\bin',
                'C:\\Windows\\System32',
                'C:\\Windows'
            ]
            
        elif self.system == 'darwin':  # macOS
            # macOS paths
            paths['go_tools'] = [
                '/usr/local/go/bin',
                '/opt/homebrew/bin',
                os.path.expanduser('~/go/bin'),
                '/usr/local/bin'
            ]
            paths['python_tools'] = [
                '/usr/local/bin',
                '/opt/homebrew/bin',
                os.path.expanduser('~/.local/bin'),
                '/usr/bin'
            ]
            paths['system_tools'] = [
                '/usr/local/bin',
                '/opt/homebrew/bin',
                '/usr/bin',
                '/bin'
            ]
            
        else:  # Linux
            # Linux paths
            paths['go_tools'] = [
                '/home/ubuntu/go/bin',
                '/usr/local/go/bin',
                os.path.expanduser('~/go/bin'),
                '/usr/local/bin',
                '/usr/bin'
            ]
            paths['python_tools'] = [
                os.path.expanduser('~/.local/bin'),
                '/usr/local/bin',
                '/usr/bin'
            ]
            paths['system_tools'] = [
                '/usr/local/bin',
                '/usr/bin',
                '/bin',
                '/usr/sbin',
                '/sbin'
            ]
        
        return paths
    
    def _setup_environment(self):
        """Setup environment variables for cross-platform compatibility"""
        # Add all tool paths to PATH
        all_paths = []
        for category, paths in self.paths.items():
            for path in paths:
                if path and os.path.exists(path) and path not in all_paths:
                    all_paths.append(path)
        
        # Update PATH
        current_path = os.environ.get('PATH', '')
        new_paths = [p for p in all_paths if p not in current_path.split(os.pathsep)]
        
        if new_paths:
            os.environ['PATH'] = current_path + os.pathsep + os.pathsep.join(new_paths)
            print(f"🔧 Added {len(new_paths)} paths to PATH for {self.system}")
    
    def find_tool(self, tool_name: str) -> Optional[str]:
        """Find tool executable path across platforms"""
        # Try direct command first
        try:
            result = subprocess.run(['which', tool_name] if self.system != 'windows' else ['where', tool_name], 
                                  capture_output=True, timeout=5)
            if result.returncode == 0:
                path = result.stdout.decode().strip().split('\n')[0]
                if os.path.exists(path):
                    return path
        except:
            pass
        
        # Try different extensions on Windows
        extensions = ['']
        if self.system == 'windows':
            extensions.extend(['.exe', '.cmd', '.bat'])
        
        # Search in all paths
        for extension in extensions:
            tool_with_ext = tool_name + extension
            
            for category, paths in self.paths.items():
                for path in paths:
                    if path and os.path.exists(path):
                        full_path = os.path.join(path, tool_with_ext)
                        if os.path.exists(full_path) and os.access(full_path, os.X_OK):
                            return full_path
        
        return None
    
    def is_tool_available(self, tool_name: str) -> bool:
        """Check if tool is available on current platform"""
        return self.find_tool(tool_name) is not None
    
    def run_tool(self, tool_name: str, args: List[str], timeout: int = 300) -> Dict[str, Any]:
        """Run tool with platform-specific handling"""
        tool_path = self.find_tool(tool_name)
        
        if not tool_path:
            return {
                'success': False,
                'error': f'{tool_name} not found on {self.system}',
                'tool': tool_name
            }
        
        try:
            cmd = [tool_path] + args
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            
            return {
                'success': True,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'returncode': result.returncode,
                'tool': tool_name,
                'tool_path': tool_path
            }
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'error': f'{tool_name} timed out after {timeout}s',
                'tool': tool_name
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'tool': tool_name
            }
    
    def get_platform_info(self) -> Dict[str, Any]:
        """Get detailed platform information"""
        return {
            'system': self.system,
            'platform': platform.platform(),
            'architecture': platform.architecture(),
            'machine': platform.machine(),
            'processor': platform.processor(),
            'python_version': platform.python_version(),
            'paths': self.paths
        }

# Global platform manager instance
platform_manager = PlatformManager()

def get_platform_manager() -> PlatformManager:
    """Get global platform manager instance"""
    return platform_manager

if __name__ == "__main__":
    # Test platform manager
    pm = get_platform_manager()
    print("🔍 Platform Information:")
    info = pm.get_platform_info()
    for key, value in info.items():
        print(f"  {key}: {value}")
    
    print(f"\n🛠️ Tool Availability:")
    tools = ['python', 'pip', 'go', 'git', 'sublist3r', 'subfinder', 'httpx', 'gobuster']
    for tool in tools:
        available = pm.is_tool_available(tool)
        path = pm.find_tool(tool)
        status = "✅" if available else "❌"
        print(f"  {status} {tool}: {path if path else 'Not found'}")