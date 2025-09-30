"""
ARAT Simple Web Panel - No Database Version
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Any
from pathlib import Path

from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit, join_room, leave_room
import threading
import uuid

class SimpleWebPanel:
    """Simple ARAT web panel without database"""
    
    def __init__(self):
        # Flask app
        self.app = Flask(__name__, 
                        template_folder=str(Path(__file__).parent / 'templates'),
                        static_folder=str(Path(__file__).parent / 'static'))
        self.app.secret_key = "your-secret-key-here"
        
        # SocketIO for real-time updates
        self.socketio = SocketIO(self.app, cors_allowed_origins="*")
        
        # Simple data storage
        self.targets = []
        self.active_tasks = {}
        
        # Setup routes
        self._setup_routes()
        self._setup_socketio_events()
        
        print("✅ Simple Web Panel initialized")
    
    def _setup_routes(self):
        """Setup routes"""
        
        @self.app.route('/')
        def index():
            """Home page"""
            return render_template('simple_index.html')
        
        @self.app.route('/dashboard')
        def dashboard():
            """Main dashboard"""
            return render_template('simple_dashboard.html')
        
        @self.app.route('/targets')
        def targets():
            """Target management"""
            return render_template('simple_targets.html')
        
        @self.app.route('/phases')
        def phases():
            """Phase management"""
            return render_template('simple_phases.html')
        
        @self.app.route('/reports')
        def reports():
            """Reports"""
            return render_template('simple_reports.html')
        
        @self.app.route('/settings')
        def settings():
            """Settings"""
            return render_template('simple_settings.html')
        
        @self.app.route('/api/targets', methods=['GET', 'POST'])
        def api_targets():
            """API for target management"""
            if request.method == 'GET':
                try:
                    return jsonify({'success': True, 'targets': self.targets})
                except Exception as e:
                    return jsonify({'success': False, 'error': str(e)})
            
            elif request.method == 'POST':
                try:
                    data = request.json
                    target = data.get('target')
                    description = data.get('description', '')
                    
                    if not target:
                        return jsonify({'success': False, 'error': 'Target not specified'})
                    
                    # Add target
                    new_target = {
                        'id': len(self.targets) + 1,
                        'target': target,
                        'description': description,
                        'created_at': datetime.now().isoformat(),
                        'status': 'ready',
                        'phases_completed': 0
                    }
                    self.targets.append(new_target)
                    
                    return jsonify({'success': True, 'target_id': new_target['id'], 'message': 'Target added successfully'})
                
                except Exception as e:
                    return jsonify({'success': False, 'error': str(e)})
        
        @self.app.route('/api/phases', methods=['GET'])
        def api_phases():
            """Get available phases"""
            try:
                phases = [
                    {"number": 1, "name": "Real IP Extraction", "description": "Extract real IP address", "dependencies": []},
                    {"number": 2, "name": "Subdomain Discovery", "description": "Discover subdomains", "dependencies": [1]}
                ]
                return jsonify({'success': True, 'phases': phases})
            except Exception as e:
                return jsonify({'success': False, 'error': str(e)})
        
        @self.app.route('/api/run', methods=['POST'])
        def api_run():
            """Run reconnaissance"""
            try:
                data = request.json
                target = data.get('target')
                phases = data.get('phases', [])
                
                if not target:
                    return jsonify({'success': False, 'error': 'Target not specified'})
                
                # Create task ID
                task_id = str(uuid.uuid4())
                
                # Start task in background
                self._start_recon_task(task_id, target, phases)
                
                return jsonify({
                    'success': True, 
                    'task_id': task_id,
                    'message': 'Reconnaissance started'
                })
                
            except Exception as e:
                return jsonify({'success': False, 'error': str(e)})
        
        @self.app.route('/api/tasks/<task_id>', methods=['GET'])
        def api_task_status(task_id):
            """Task status"""
            try:
                if task_id in self.active_tasks:
                    task_info = self.active_tasks[task_id]
                    return jsonify({'success': True, 'task': task_info})
                else:
                    return jsonify({'success': False, 'error': 'Task not found'})
            except Exception as e:
                return jsonify({'success': False, 'error': str(e)})
        
        @self.app.route('/api/results/<target>', methods=['GET'])
        def api_results(target):
            """Get results"""
            try:
                # Simple results
                results = {
                    'target': target,
                    'phases': {
                        'phase_1': {'status': 'completed', 'results': {'ips_found': 1}},
                        'phase_2': {'status': 'completed', 'results': {'subdomains_found': 5}}
                    },
                    'summary': {
                        'total_phases': 2,
                        'completed_phases': 2,
                        'subdomains_found': 5,
                        'vulnerabilities_found': 0
                    }
                }
                return jsonify({'success': True, 'results': results})
            except Exception as e:
                return jsonify({'success': False, 'error': str(e)})
        
        @self.app.route('/api/settings', methods=['GET', 'POST'])
        def api_settings():
            """Settings"""
            if request.method == 'GET':
                try:
                    settings = {
                        'api_keys': {},
                        'phases': {
                            'max_workers': 10,
                            'timeout': 30,
                            'enable_parallel': True
                        },
                        'web': {
                            'host': '127.0.0.1',
                            'port': 8080,
                            'debug': False
                        }
                    }
                    return jsonify({'success': True, 'settings': settings})
                except Exception as e:
                    return jsonify({'success': False, 'error': str(e)})
            
            elif request.method == 'POST':
                try:
                    data = request.json
                    return jsonify({'success': True, 'message': 'Settings updated'})
                except Exception as e:
                    return jsonify({'success': False, 'error': str(e)})
    
    def _setup_socketio_events(self):
        """Setup SocketIO events"""
        
        @self.socketio.on('connect')
        def handle_connect():
            """User connection"""
            print(f"✅ User connected: {request.sid}")
            emit('status', {'message': 'Connected'})
        
        @self.socketio.on('disconnect')
        def handle_disconnect():
            """User disconnection"""
            print(f"❌ User disconnected: {request.sid}")
        
        @self.socketio.on('join_task')
        def handle_join_task(data):
            """Join task"""
            task_id = data.get('task_id')
            if task_id:
                join_room(f'task_{task_id}')
                emit('joined_task', {'task_id': task_id})
        
        @self.socketio.on('leave_task')
        def handle_leave_task(data):
            """Leave task"""
            task_id = data.get('task_id')
            if task_id:
                leave_room(f'task_{task_id}')
                emit('left_task', {'task_id': task_id})
    
    def _start_recon_task(self, task_id: str, target: str, phases: List[int]):
        """Start reconnaissance task"""
        try:
            # Register task
            self.active_tasks[task_id] = {
                'id': task_id,
                'target': target,
                'phases': phases,
                'status': 'running',
                'start_time': datetime.now().isoformat(),
                'current_phase': None,
                'progress': 0,
                'results': {},
                'errors': []
            }
            
            # Start task in separate thread
            thread = threading.Thread(target=self._run_recon_task, args=(task_id, target, phases))
            thread.daemon = True
            thread.start()
            
            print(f"✅ Task {task_id} started for {target}")
            
        except Exception as e:
            print(f"❌ Error starting task {task_id}: {e}")
            if task_id in self.active_tasks:
                self.active_tasks[task_id]['status'] = 'error'
                self.active_tasks[task_id]['errors'].append(str(e))
    
    def _run_recon_task(self, task_id: str, target: str, phases: List[int]):
        """Run reconnaissance task"""
        try:
            # If no phases specified, run all available phases
            if not phases:
                phases = [1, 2]  # Only available phases
            
            total_phases = len(phases)
            
            for i, phase_num in enumerate(phases):
                try:
                    # Update status
                    self.active_tasks[task_id]['current_phase'] = phase_num
                    self.active_tasks[task_id]['progress'] = int((i / total_phases) * 100)
                    
                    # Send real-time update
                    self.socketio.emit('task_update', {
                        'task_id': task_id,
                        'status': 'running',
                        'current_phase': phase_num,
                        'progress': self.active_tasks[task_id]['progress'],
                        'message': f'Phase {phase_num} running...'
                    }, room=f'task_{task_id}')
                    
                    # Simulate phase execution
                    import time
                    time.sleep(2)  # Simulate work
                    
                    # Simulate result
                    result = {
                        'phase': phase_num,
                        'target': target,
                        'status': 'completed',
                        'results': {
                            'ips_found': 1 if phase_num == 1 else 0,
                            'subdomains_found': 5 if phase_num == 2 else 0
                        }
                    }
                    
                    # Save result
                    self.active_tasks[task_id]['results'][f'phase_{phase_num}'] = result
                    
                    # Send update
                    self.socketio.emit('phase_completed', {
                        'task_id': task_id,
                        'phase': phase_num,
                        'result': result,
                        'message': f'Phase {phase_num} completed'
                    }, room=f'task_{task_id}')
                    
                except Exception as e:
                    error_msg = f"Error in phase {phase_num}: {str(e)}"
                    self.active_tasks[task_id]['errors'].append(error_msg)
                    
                    self.socketio.emit('phase_error', {
                        'task_id': task_id,
                        'phase': phase_num,
                        'error': str(e),
                        'message': error_msg
                    }, room=f'task_{task_id}')
                    
                    print(f"❌ {error_msg}")
            
            # Complete task
            self.active_tasks[task_id]['status'] = 'completed'
            self.active_tasks[task_id]['progress'] = 100
            self.active_tasks[task_id]['end_time'] = datetime.now().isoformat()
            
            # Send completion message
            self.socketio.emit('task_completed', {
                'task_id': task_id,
                'message': 'Reconnaissance completed',
                'results': self.active_tasks[task_id]['results']
            }, room=f'task_{task_id}')
            
            print(f"✅ Task {task_id} completed")
            
        except Exception as e:
            error_msg = f"Error in task {task_id}: {str(e)}"
            self.active_tasks[task_id]['status'] = 'error'
            self.active_tasks[task_id]['errors'].append(error_msg)
            
            self.socketio.emit('task_error', {
                'task_id': task_id,
                'error': str(e),
                'message': error_msg
            }, room=f'task_{task_id}')
            
            print(f"❌ {error_msg}")
    
    def start(self, host: str = "0.0.0.0", port: int = 8080):
        """Start web panel"""
        try:
            print(f"🌐 Starting simple web panel on {host}:{port}")
            self.socketio.run(
                self.app,
                host=host,
                port=port,
                debug=False,
                allow_unsafe_werkzeug=True
            )
        except Exception as e:
            print(f"❌ Error starting web panel: {e}")
            raise