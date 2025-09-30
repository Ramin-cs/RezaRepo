"""
پنل وب ARAT - رابط کاربری پیشرفته
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
    """کلاس اصلی پنل وب ARAT"""
    
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
        
        self.logger.info("پنل وب ARAT مقداردهی شد")
    
    def _setup_routes(self):
        """تنظیم routes"""
        
        @self.app.route('/')
        def index():
            """صفحه اصلی"""
            return render_template('index.html')
        
        @self.app.route('/dashboard')
        def dashboard():
            """داشبورد اصلی"""
            return render_template('dashboard.html')
        
        @self.app.route('/targets')
        def targets():
            """مدیریت اهداف"""
            return render_template('targets.html')
        
        @self.app.route('/phases')
        def phases():
            """مدیریت فازها"""
            return render_template('phases.html')
        
        @self.app.route('/reports')
        def reports():
            """گزارش‌ها"""
            return render_template('reports.html')
        
        @self.app.route('/settings')
        def settings():
            """تنظیمات"""
            return render_template('settings.html')
        
        @self.app.route('/api/targets', methods=['GET', 'POST'])
        def api_targets():
            """API برای مدیریت اهداف"""
            if request.method == 'GET':
                # دریافت لیست اهداف
                try:
                    targets = self._get_targets()
                    return jsonify({'success': True, 'targets': targets})
                except Exception as e:
                    return jsonify({'success': False, 'error': str(e)})
            
            elif request.method == 'POST':
                # اضافه کردن هدف جدید
                try:
                    data = request.json
                    target = data.get('target')
                    description = data.get('description', '')
                    
                    if not target:
                        return jsonify({'success': False, 'error': 'هدف مشخص نشده'})
                    
                    # ذخیره هدف
                    target_id = asyncio.run(self.db.save_target(target, metadata={'description': description}))
                    
                    return jsonify({'success': True, 'target_id': target_id, 'message': 'هدف با موفقیت اضافه شد'})
                
                except Exception as e:
                    return jsonify({'success': False, 'error': str(e)})
        
        @self.app.route('/api/targets/<int:target_id>', methods=['DELETE'])
        def api_delete_target(target_id):
            """حذف هدف"""
            try:
                # TODO: پیاده‌سازی حذف هدف
                return jsonify({'success': True, 'message': 'هدف حذف شد'})
            except Exception as e:
                return jsonify({'success': False, 'error': str(e)})
        
        @self.app.route('/api/phases', methods=['GET'])
        def api_phases():
            """دریافت لیست فازهای موجود"""
            try:
                phases = asyncio.run(self.phase_manager.get_available_phases())
                return jsonify({'success': True, 'phases': phases})
            except Exception as e:
                return jsonify({'success': False, 'error': str(e)})
        
        @self.app.route('/api/run', methods=['POST'])
        def api_run():
            """اجرای reconnaissance"""
            try:
                data = request.json
                target = data.get('target')
                phases = data.get('phases', [])
                
                if not target:
                    return jsonify({'success': False, 'error': 'هدف مشخص نشده'})
                
                # ایجاد task ID
                task_id = str(uuid.uuid4())
                
                # شروع task در background
                self._start_recon_task(task_id, target, phases)
                
                return jsonify({
                    'success': True, 
                    'task_id': task_id,
                    'message': 'Reconnaissance شروع شد'
                })
                
            except Exception as e:
                return jsonify({'success': False, 'error': str(e)})
        
        @self.app.route('/api/tasks/<task_id>', methods=['GET'])
        def api_task_status(task_id):
            """وضعیت task"""
            try:
                if task_id in self.active_tasks:
                    task_info = self.active_tasks[task_id]
                    return jsonify({'success': True, 'task': task_info})
                else:
                    return jsonify({'success': False, 'error': 'Task پیدا نشد'})
            except Exception as e:
                return jsonify({'success': False, 'error': str(e)})
        
        @self.app.route('/api/results/<target>', methods=['GET'])
        def api_results(target):
            """دریافت نتایج"""
            try:
                results = self._get_target_results(target)
                return jsonify({'success': True, 'results': results})
            except Exception as e:
                return jsonify({'success': False, 'error': str(e)})
        
        @self.app.route('/api/settings', methods=['GET', 'POST'])
        def api_settings():
            """تنظیمات"""
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
                    return jsonify({'success': True, 'message': 'تنظیمات به‌روزرسانی شد'})
                except Exception as e:
                    return jsonify({'success': False, 'error': str(e)})
        
        @self.app.route('/api/logs', methods=['GET'])
        def api_logs():
            """دریافت لاگ‌ها"""
            try:
                logs = self._get_recent_logs()
                return jsonify({'success': True, 'logs': logs})
            except Exception as e:
                return jsonify({'success': False, 'error': str(e)})
    
    def _setup_socketio_events(self):
        """تنظیم SocketIO events"""
        
        @self.socketio.on('connect')
        def handle_connect():
            """اتصال کاربر"""
            self.logger.info(f"کاربر متصل شد: {request.sid}")
            emit('status', {'message': 'متصل شدید'})
        
        @self.socketio.on('disconnect')
        def handle_disconnect():
            """قطع اتصال کاربر"""
            self.logger.info(f"کاربر قطع شد: {request.sid}")
        
        @self.socketio.on('join_task')
        def handle_join_task(data):
            """پیوستن به task"""
            task_id = data.get('task_id')
            if task_id:
                join_room(f'task_{task_id}')
                emit('joined_task', {'task_id': task_id})
        
        @self.socketio.on('leave_task')
        def handle_leave_task(data):
            """ترک task"""
            task_id = data.get('task_id')
            if task_id:
                leave_room(f'task_{task_id}')
                emit('left_task', {'task_id': task_id})
    
    def _start_recon_task(self, task_id: str, target: str, phases: List[int]):
        """شروع task reconnaissance"""
        try:
            # ثبت task
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
            
            # شروع task در thread جداگانه
            thread = threading.Thread(target=self._run_recon_task, args=(task_id, target, phases))
            thread.daemon = True
            thread.start()
            
            self.logger.info(f"Task {task_id} شروع شد برای {target}")
            
        except Exception as e:
            self.logger.error(f"خطا در شروع task {task_id}: {e}")
            if task_id in self.active_tasks:
                self.active_tasks[task_id]['status'] = 'error'
                self.active_tasks[task_id]['errors'].append(str(e))
    
    def _run_recon_task(self, task_id: str, target: str, phases: List[int]):
        """اجرای task reconnaissance"""
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            # اگر phases مشخص نشده، تمام فازها
            if not phases:
                phases = [1, 2]  # فقط فازهای موجود
            
            total_phases = len(phases)
            
            for i, phase_num in enumerate(phases):
                try:
                    # به‌روزرسانی وضعیت
                    self.active_tasks[task_id]['current_phase'] = phase_num
                    self.active_tasks[task_id]['progress'] = int((i / total_phases) * 100)
                    
                    # ارسال به‌روزرسانی real-time
                    self.socketio.emit('task_update', {
                        'task_id': task_id,
                        'status': 'running',
                        'current_phase': phase_num,
                        'progress': self.active_tasks[task_id]['progress'],
                        'message': f'فاز {phase_num} در حال اجرا...'
                    }, room=f'task_{task_id}')
                    
                    # اجرای فاز
                    result = loop.run_until_complete(
                        self.phase_manager.run_phase(phase_num, target)
                    )
                    
                    # ذخیره نتیجه
                    self.active_tasks[task_id]['results'][f'phase_{phase_num}'] = result
                    
                    # ارسال به‌روزرسانی
                    self.socketio.emit('phase_completed', {
                        'task_id': task_id,
                        'phase': phase_num,
                        'result': result,
                        'message': f'فاز {phase_num} تکمیل شد'
                    }, room=f'task_{task_id}')
                    
                except Exception as e:
                    error_msg = f"خطا در فاز {phase_num}: {str(e)}"
                    self.active_tasks[task_id]['errors'].append(error_msg)
                    
                    self.socketio.emit('phase_error', {
                        'task_id': task_id,
                        'phase': phase_num,
                        'error': str(e),
                        'message': error_msg
                    }, room=f'task_{task_id}')
                    
                    self.logger.error(error_msg)
            
            # تکمیل task
            self.active_tasks[task_id]['status'] = 'completed'
            self.active_tasks[task_id]['progress'] = 100
            self.active_tasks[task_id]['end_time'] = datetime.now().isoformat()
            
            # ارسال پیام تکمیل
            self.socketio.emit('task_completed', {
                'task_id': task_id,
                'message': 'Reconnaissance تکمیل شد',
                'results': self.active_tasks[task_id]['results']
            }, room=f'task_{task_id}')
            
            self.logger.info(f"Task {task_id} تکمیل شد")
            
        except Exception as e:
            error_msg = f"خطا در task {task_id}: {str(e)}"
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
        """دریافت لیست اهداف"""
        try:
            # TODO: پیاده‌سازی دریافت اهداف از دیتابیس
            return [
                {
                    'id': 1,
                    'target': 'example.com',
                    'description': 'هدف نمونه',
                    'created_at': datetime.now().isoformat(),
                    'status': 'completed',
                    'phases_completed': 2
                }
            ]
        except Exception as e:
            self.logger.error(f"خطا در دریافت اهداف: {e}")
            return []
    
    def _get_target_results(self, target: str) -> Dict[str, Any]:
        """دریافت نتایج هدف"""
        try:
            # TODO: پیاده‌سازی دریافت نتایج از دیتابیس
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
            self.logger.error(f"خطا در دریافت نتایج {target}: {e}")
            return {}
    
    def _get_settings(self) -> Dict[str, Any]:
        """دریافت تنظیمات"""
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
            self.logger.error(f"خطا در دریافت تنظیمات: {e}")
            return {}
    
    def _update_settings(self, settings: Dict[str, Any]):
        """به‌روزرسانی تنظیمات"""
        try:
            # به‌روزرسانی API keys
            if 'api_keys' in settings:
                for service, key in settings['api_keys'].items():
                    self.config.update_config('api_keys', service, key)
            
            # به‌روزرسانی تنظیمات فازها
            if 'phases' in settings:
                for key, value in settings['phases'].items():
                    self.config.update_config('phases', key, value)
            
            self.logger.info("تنظیمات به‌روزرسانی شد")
            
        except Exception as e:
            self.logger.error(f"خطا در به‌روزرسانی تنظیمات: {e}")
            raise
    
    def _get_recent_logs(self) -> List[Dict[str, Any]]:
        """دریافت لاگ‌های اخیر"""
        try:
            # TODO: پیاده‌سازی دریافت لاگ‌ها
            return [
                {
                    'timestamp': datetime.now().isoformat(),
                    'level': 'INFO',
                    'message': 'سیستم شروع شد',
                    'source': 'web_panel'
                }
            ]
        except Exception as e:
            self.logger.error(f"خطا در دریافت لاگ‌ها: {e}")
            return []
    
    def start(self, host: str = "0.0.0.0", port: int = 8080):
        """شروع پنل وب"""
        try:
            self.logger.info(f"شروع پنل وب روی {host}:{port}")
            self.socketio.run(
                self.app,
                host=host,
                port=port,
                debug=self.config.web.debug,
                allow_unsafe_werkzeug=True
            )
        except Exception as e:
            self.logger.error(f"خطا در شروع پنل وب: {e}")
            raise
    
    async def stop(self):
        """توقف پنل وب"""
        try:
            self.logger.info("توقف پنل وب...")
            # TODO: پیاده‌سازی توقف graceful
        except Exception as e:
            self.logger.error(f"خطا در توقف پنل وب: {e}")