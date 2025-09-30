"""
ARAT Web Panel - Advanced User Interface
"""

import asyncio
import json
from datetime import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path
import logging

from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session
from flask_socketio import SocketIO, emit, join_room, leave_room
import threading
import uuid

from core.config import Config
from core.database import Database
from phases.phase_manager import PhaseManager


class WebPanel:
    """Main ARAT web panel class"""
    
    def __init__(self, config: Config, database: Database, phase_manager: PhaseManager):
        self.config = config
        self.db = database
        self.phase_manager = phase_manager
        self.logger = logging.getLogger('arat.web_panel')
        
        # Flask app
        self.app = Flask(__name__, 
                        template_folder=str(Path(__file__).parent / 'templates'),
                        static_folder=str(Path(__file__).parent / 'static'))
        self.app.secret_key = self.config.web.secret_key
        
        # SocketIO for real-time updates
        self.socketio = SocketIO(self.app, cors_allowed_origins="*")
        
        # Active tasks
        self.active_tasks = {}
        
        # Setup routes
        self._setup_routes()
        self._setup_socketio_events()
        
        self.logger.info("ARAT Web Panel initialized")
    
    def _setup_routes(self):
        """Setup routes"""
        
        @self.app.route('/')
        def index():
            """Home page"""
            return render_template('index.html')
        
        @self.app.route('/dashboard')
        def dashboard():
            """Main dashboard"""
            return render_template('dashboard.html')
        
        @self.app.route('/targets')
        def targets():
            """Target management"""
            return render_template('targets.html')
        
        @self.app.route('/phases')
        def phases():
            """Phase management"""
            return render_template('phases.html')
        
        @self.app.route('/reports')
        def reports():
            """Reports"""
            return render_template('reports.html')
        
        @self.app.route('/settings')
        def settings():
            """Settings"""
            return render_template('settings.html')
        
        @self.app.route('/api/targets', methods=['GET', 'POST'])
        def api_targets():
            """API for target management"""
            if request.method == 'GET':
                # Get targets list
                try:
                    targets = self._get_targets()
                    return jsonify({'success': True, 'targets': targets})
                except Exception as e:
                    return jsonify({'success': False, 'error': str(e)})
            
            elif request.method == 'POST':
                # Add new target
                try:
                    data = request.json
                    target = data.get('target')
                    description = data.get('description', '')
                    
                    if not target:
                        return jsonify({'success': False, 'error': 'Target not specified'})
                    
                    # Save target
                    target_id = asyncio.run(self.db.save_target(target, metadata={'description': description}))
                    
                    return jsonify({'success': True, 'target_id': target_id, 'message': 'Target added successfully'})
                
                except Exception as e:
                    return jsonify({'success': False, 'error': str(e)})
        
        @self.app.route('/api/targets/<int:target_id>', methods=['DELETE'])
        def api_delete_target(target_id):
            """Delete target"""
            try:
                # TODO: Implement target deletion
                return jsonify({'success': True, 'message': 'Target deleted'})
            except Exception as e:
                return jsonify({'success': False, 'error': str(e)})
        
        @self.app.route('/api/phases', methods=['GET'])
        def api_phases():
            """Get available phases"""
            try:
                phases = asyncio.run(self.phase_manager.get_available_phases())
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
                results = self._get_target_results(target)
                return jsonify({'success': True, 'results': results})
            except Exception as e:
                return jsonify({'success': False, 'error': str(e)})
        
        @self.app.route('/api/settings', methods=['GET', 'POST'])
        def api_settings():
            """Settings"""
            if request.method == 'GET':
                try:
                    settings = self._get_settings()
                    return jsonify({'success': True, 'settings': settings})
                except Exception as e:
                    return jsonify({'success': False, 'error': str(e)})
            
            elif request.method == 'POST':
                try:
                    data = request.json
                    self._update_settings(data)
                    return jsonify({'success': True, 'message': 'Settings updated'})
                except Exception as e:
                    return jsonify({'success': False, 'error': str(e)})
        
        @self.app.route('/api/logs', methods=['GET'])
        def api_logs():
            """Get logs"""
            try:
                logs = self._get_recent_logs()
                return jsonify({'success': True, 'logs': logs})
            except Exception as e:
                return jsonify({'success': False, 'error': str(e)})
    
    def _setup_socketio_events(self):
        """Setup SocketIO events"""
        
        @self.socketio.on('connect')
        def handle_connect():
            """User connection"""
            self.logger.info(f"User connected: {request.sid}")
            emit('status', {'message': 'Connected'})
        
        @self.socketio.on('disconnect')
        def handle_disconnect():
            """User disconnection"""
            self.logger.info(f"User disconnected: {request.sid}")
        
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
            
            self.logger.info(f"Task {task_id} started for {target}")
            
        except Exception as e:
            self.logger.error(f"Error starting task {task_id}: {e}")
            if task_id in self.active_tasks:
                self.active_tasks[task_id]['status'] = 'error'
                self.active_tasks[task_id]['errors'].append(str(e))
    
    def _run_recon_task(self, task_id: str, target: str, phases: List[int]):
        """Run reconnaissance task"""
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
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
                    
                    # Run phase
                    result = loop.run_until_complete(
                        self.phase_manager.run_phase(phase_num, target)
                    )
                    
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
                    
                    self.logger.error(error_msg)
            
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
            
            self.logger.info(f"Task {task_id} completed")
            
        except Exception as e:
            error_msg = f"Error in task {task_id}: {str(e)}"
            self.active_tasks[task_id]['status'] = 'error'
            self.active_tasks[task_id]['errors'].append(error_msg)
            
            self.socketio.emit('task_error', {
                'task_id': task_id,
                'error': str(e),
                'message': error_msg
            }, room=f'task_{task_id}')
            
            self.logger.error(error_msg)
        
        finally:
            loop.close()
    
    def _get_targets(self) -> List[Dict[str, Any]]:
        """Get targets list"""
        try:
            # TODO: Implement getting targets from database
            return [
                {
                    'id': 1,
                    'target': 'example.com',
                    'description': 'Sample target',
                    'created_at': datetime.now().isoformat(),
                    'status': 'completed',
                    'phases_completed': 2
                }
            ]
        except Exception as e:
            self.logger.error(f"Error getting targets: {e}")
            return []
    
    def _get_target_results(self, target: str) -> Dict[str, Any]:
        """Get target results"""
        try:
            # TODO: Implement getting results from database
            return {
                'target': target,
                'phases': {},
                'summary': {
                    'total_phases': 2,
                    'completed_phases': 2,
                    'subdomains_found': 0,
                    'vulnerabilities_found': 0
                }
            }
        except Exception as e:
            self.logger.error(f"Error getting results for {target}: {e}")
            return {}
    
    def _get_settings(self) -> Dict[str, Any]:
        """Get settings"""
        try:
            return {
                'api_keys': self.config.api_keys,
                'phases': {
                    'max_workers': self.config.phases.max_workers,
                    'timeout': self.config.phases.timeout,
                    'enable_parallel': self.config.phases.enable_parallel
                },
                'web': {
                    'host': self.config.web.host,
                    'port': self.config.web.port,
                    'debug': self.config.web.debug
                }
            }
        except Exception as e:
            self.logger.error(f"Error getting settings: {e}")
            return {}
    
    def _update_settings(self, settings: Dict[str, Any]):
        """Update settings"""
        try:
            # Update API keys
            if 'api_keys' in settings:
                for service, key in settings['api_keys'].items():
                    self.config.update_config('api_keys', service, key)
            
            # Update phase settings
            if 'phases' in settings:
                for key, value in settings['phases'].items():
                    self.config.update_config('phases', key, value)
            
            self.logger.info("Settings updated")
            
        except Exception as e:
            self.logger.error(f"Error updating settings: {e}")
            raise
    
    def _get_recent_logs(self) -> List[Dict[str, Any]]:
        """Get recent logs"""
        try:
            # TODO: Implement getting logs
            return [
                {
                    'timestamp': datetime.now().isoformat(),
                    'level': 'INFO',
                    'message': 'System started',
                    'source': 'web_panel'
                }
            ]
        except Exception as e:
            self.logger.error(f"Error getting logs: {e}")
            return []
    
    def start(self, host: str = "0.0.0.0", port: int = 8080):
        """Start web panel"""
        try:
            self.logger.info(f"Starting web panel on {host}:{port}")
            self.socketio.run(
                self.app,
                host=host,
                port=port,
                debug=self.config.web.debug,
                allow_unsafe_werkzeug=True
            )
        except Exception as e:
            self.logger.error(f"Error starting web panel: {e}")
            raise
    
    async def stop(self):
        """Stop web panel"""
        try:
            self.logger.info("Stopping web panel...")
            # TODO: Implement graceful shutdown
        except Exception as e:
            self.logger.error(f"Error stopping web panel: {e}")