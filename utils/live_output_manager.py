#!/usr/bin/env python3
"""
Live Output Manager for ARAT
Captures console output and sends to frontend via Socket.IO
"""

import sys
import io
import threading
from typing import Optional, Callable

class LiveOutputCapture:
    """Capture stdout and send to frontend"""
    
    def __init__(self, socketio=None, task_id=None, room=None):
        self.socketio = socketio
        self.task_id = task_id
        self.room = room
        self.original_stdout = sys.stdout
        self.original_stderr = sys.stderr
        self.buffer = io.StringIO()
        self.lock = threading.Lock()
        
    def write(self, text):
        """Write to buffer and emit to frontend"""
        with self.lock:
            # Write to original stdout (console)
            self.original_stdout.write(text)
            self.original_stdout.flush()
            
            # Write to buffer
            self.buffer.write(text)
            
            # Send to frontend if socketio available
            if self.socketio and self.task_id and text.strip():
                try:
                    self.socketio.emit('phase_output', {
                        'task_id': self.task_id,
                        'phase': 'live',
                        'output': text.strip()
                    }, room=self.room)
                except Exception as e:
                    # Fallback: write to original stderr
                    self.original_stderr.write(f"Live output error: {e}\n")
    
    def flush(self):
        """Flush buffer"""
        self.original_stdout.flush()
        self.buffer.flush()
    
    def get_output(self):
        """Get captured output"""
        return self.buffer.getvalue()

class LiveOutputManager:
    """Manage live output for phases"""
    
    def __init__(self, socketio=None):
        self.socketio = socketio
        self.active_captures = {}
        
    def start_capture(self, task_id: str, phase: int = None):
        """Start capturing output for a task/phase"""
        room = f'task_{task_id}'
        capture = LiveOutputCapture(self.socketio, task_id, room)
        
        # Store capture
        if task_id not in self.active_captures:
            self.active_captures[task_id] = {}
        self.active_captures[task_id][phase or 'general'] = capture
        
        # Redirect stdout
        sys.stdout = capture
        
        # Emit phase start
        if self.socketio and phase:
            self.socketio.emit('phase_started', {
                'task_id': task_id,
                'phase': phase,
                'name': self._get_phase_name(phase),
                'message': f'Starting Phase {phase}: {self._get_phase_name(phase)}...'
            }, room=room)
    
    def stop_capture(self, task_id: str, phase: int = None):
        """Stop capturing output for a task/phase"""
        if task_id in self.active_captures:
            phase_key = phase or 'general'
            if phase_key in self.active_captures[task_id]:
                capture = self.active_captures[task_id][phase_key]
                
                # Restore stdout
                sys.stdout = capture.original_stdout
                
                # Get captured output
                output = capture.get_output()
                
                # Emit phase completion
                if self.socketio and phase:
                    self.socketio.emit('phase_completed', {
                        'task_id': task_id,
                        'phase': phase,
                        'summary': f'Phase {phase} completed',
                        'output': output
                    }, room=f'task_{task_id}')
                
                # Remove capture
                del self.active_captures[task_id][phase_key]
    
    def emit_output(self, task_id: str, message: str, phase: int = None):
        """Emit a message to live output"""
        if self.socketio:
            self.socketio.emit('phase_output', {
                'task_id': task_id,
                'phase': phase or 'live',
                'output': message
            }, room=f'task_{task_id}')
    
    def emit_phase_start(self, task_id: str, phase: int, target: str):
        """Emit phase start message"""
        if self.socketio:
            self.socketio.emit('phase_started', {
                'task_id': task_id,
                'phase': phase,
                'name': self._get_phase_name(phase),
                'target': target,
                'message': f'Starting Phase {phase}: {self._get_phase_name(phase)} for {target}...'
            }, room=f'task_{task_id}')
    
    def emit_phase_completion(self, task_id: str, phase: int, summary: str, findings: list = None):
        """Emit phase completion message"""
        if self.socketio:
            data = {
                'task_id': task_id,
                'phase': phase,
                'name': self._get_phase_name(phase),
                'summary': summary,
                'findings': findings or []
            }
            self.socketio.emit('phase_completed', data, room=f'task_{task_id}')
    
    def _get_phase_name(self, phase: int) -> str:
        """Get phase name"""
        phase_names = {
            1: 'Real IP Extraction',
            2: 'Subdomain Discovery',
            3: 'Port Scanning',
            4: 'Technology Detection',
            5: 'Directory Discovery',
            6: 'Parameter Discovery',
            7: 'Endpoint Discovery',
            8: 'Cloud Analysis',
            9: 'OSINT Analysis',
            10: 'Vulnerability Assessment'
        }
        return phase_names.get(phase, f'Phase {phase}')

# Global instance
live_output_manager = None

def init_live_output_manager(socketio):
    """Initialize global live output manager"""
    global live_output_manager
    live_output_manager = LiveOutputManager(socketio)

def get_live_output_manager():
    """Get global live output manager"""
    return live_output_manager