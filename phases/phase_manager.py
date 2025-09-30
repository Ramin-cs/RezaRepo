"""
مدیر فازها برای ARAT
"""

import asyncio
import importlib
from typing import Dict, List, Any, Optional
from pathlib import Path
import logging
from datetime import datetime
import traceback


class PhaseManager:
    """مدیر فازهای reconnaissance"""
    
    def __init__(self, config, database, api_manager):
        self.config = config
        self.db = database
        self.api_manager = api_manager
        self.logger = logging.getLogger('arat.phase_manager')
        self.phases = {}
        self._load_phases()
    
    def _load_phases(self):
        """بارگذاری فازها"""
        try:
            phases_dir = Path(__file__).parent
            
            for phase_file in phases_dir.glob("phase*/__init__.py"):
                phase_name = phase_file.parent.name
                phase_number = int(phase_name.replace('phase', ''))
                
                try:
                    # import کردن ماژول فاز
                    module_name = f"phases.{phase_name}"
                    module = importlib.import_module(module_name)
                    
                    # دریافت کلاس فاز
                    phase_class = getattr(module, f"Phase{phase_number}", None)
                    if phase_class:
                        self.phases[phase_number] = phase_class
                        self.logger.info(f"فاز {phase_number} بارگذاری شد")
                    else:
                        self.logger.warning(f"کلاس Phase{phase_number} در {module_name} پیدا نشد")
                        
                except Exception as e:
                    self.logger.error(f"خطا در بارگذاری فاز {phase_number}: {e}")
            
            self.logger.info(f"تعداد {len(self.phases)} فاز بارگذاری شد")
            
        except Exception as e:
            self.logger.error(f"خطا در بارگذاری فازها: {e}")
    
    async def initialize(self):
        """مقداردهی اولیه فازها"""
        try:
            for phase_number, phase_class in self.phases.items():
                phase_instance = phase_class(self.config, self.db, self.api_manager)
                if hasattr(phase_instance, 'initialize'):
                    await phase_instance.initialize()
                self.logger.info(f"فاز {phase_number} مقداردهی شد")
            
            self.logger.info("تمام فازها مقداردهی شدند")
            
        except Exception as e:
            self.logger.error(f"خطا در مقداردهی فازها: {e}")
            raise
    
    async def run_phase(self, phase_number: int, target: str, **kwargs) -> Dict[str, Any]:
        """اجرای فاز مشخص"""
        try:
            if phase_number not in self.phases:
                raise ValueError(f"فاز {phase_number} پیدا نشد")
            
            self.logger.info(f"شروع فاز {phase_number} برای {target}")
            
            # ایجاد instance فاز
            phase_class = self.phases[phase_number]
            phase_instance = phase_class(self.config, self.db, self.api_manager)
            
            # اجرای فاز
            start_time = datetime.now()
            
            try:
                result = await phase_instance.run(target, **kwargs)
                
                end_time = datetime.now()
                duration = (end_time - start_time).total_seconds()
                
                self.logger.info(f"فاز {phase_number} در {duration:.2f} ثانیه تکمیل شد")
                
                return {
                    'success': True,
                    'phase_number': phase_number,
                    'target': target,
                    'start_time': start_time.isoformat(),
                    'end_time': end_time.isoformat(),
                    'duration': duration,
                    'results': result
                }
                
            except Exception as e:
                end_time = datetime.now()
                duration = (end_time - start_time).total_seconds()
                
                self.logger.error(f"خطا در فاز {phase_number}: {e}")
                self.logger.debug(f"Traceback: {traceback.format_exc()}")
                
                return {
                    'success': False,
                    'phase_number': phase_number,
                    'target': target,
                    'start_time': start_time.isoformat(),
                    'end_time': end_time.isoformat(),
                    'duration': duration,
                    'error': str(e),
                    'traceback': traceback.format_exc()
                }
                
        except Exception as e:
            self.logger.error(f"خطا در اجرای فاز {phase_number}: {e}")
            raise
    
    async def run_phases_parallel(self, phase_numbers: List[int], target: str, **kwargs) -> Dict[int, Dict[str, Any]]:
        """اجرای چندین فاز به صورت موازی"""
        try:
            self.logger.info(f"اجرای موازی فازهای {phase_numbers} برای {target}")
            
            # ایجاد tasks
            tasks = []
            for phase_number in phase_numbers:
                if phase_number in self.phases:
                    task = self.run_phase(phase_number, target, **kwargs)
                    tasks.append((phase_number, task))
                else:
                    self.logger.warning(f"فاز {phase_number} پیدا نشد")
            
            # اجرای موازی
            results = {}
            if tasks:
                phase_results = await asyncio.gather(
                    *[task for _, task in tasks],
                    return_exceptions=True
                )
                
                for i, (phase_number, _) in enumerate(tasks):
                    result = phase_results[i]
                    if isinstance(result, Exception):
                        results[phase_number] = {
                            'success': False,
                            'error': str(result)
                        }
                    else:
                        results[phase_number] = result
            
            self.logger.info(f"اجرای موازی {len(results)} فاز تکمیل شد")
            return results
            
        except Exception as e:
            self.logger.error(f"خطا در اجرای موازی فازها: {e}")
            raise
    
    async def get_phase_status(self, target: str) -> Dict[int, Dict[str, Any]]:
        """دریافت وضعیت فازها برای هدف مشخص"""
        try:
            target_id = await self.db.get_target_id(target)
            if not target_id:
                return {}
            
            # دریافت نتایج فازها از دیتابیس
            with self.db.get_session() as session:
                from core.database import PhaseResult
                
                phase_results = session.query(PhaseResult).filter(
                    PhaseResult.target_id == target_id
                ).all()
                
                status = {}
                for phase_result in phase_results:
                    status[phase_result.phase_number] = {
                        'status': phase_result.status,
                        'start_time': phase_result.start_time.isoformat() if phase_result.start_time else None,
                        'end_time': phase_result.end_time.isoformat() if phase_result.end_time else None,
                        'duration': phase_result.duration,
                        'has_results': bool(phase_result.results_json),
                        'has_error': bool(phase_result.error_message)
                    }
                
                return status
                
        except Exception as e:
            self.logger.error(f"خطا در دریافت وضعیت فازها: {e}")
            return {}
    
    async def get_available_phases(self) -> List[Dict[str, Any]]:
        """دریافت لیست فازهای موجود"""
        try:
            phases_info = []
            
            for phase_number, phase_class in self.phases.items():
                phase_info = {
                    'number': phase_number,
                    'name': getattr(phase_class, 'name', f'Phase {phase_number}'),
                    'description': getattr(phase_class, 'description', ''),
                    'dependencies': getattr(phase_class, 'dependencies', []),
                    'parallel_safe': getattr(phase_class, 'parallel_safe', True)
                }
                phases_info.append(phase_info)
            
            return sorted(phases_info, key=lambda x: x['number'])
            
        except Exception as e:
            self.logger.error(f"خطا در دریافت فازهای موجود: {e}")
            return []
    
    async def validate_phase_dependencies(self, phase_number: int, target: str) -> bool:
        """اعتبارسنجی وابستگی‌های فاز"""
        try:
            if phase_number not in self.phases:
                return False
            
            phase_class = self.phases[phase_number]
            dependencies = getattr(phase_class, 'dependencies', [])
            
            if not dependencies:
                return True
            
            # بررسی وضعیت فازهای وابسته
            phase_status = await self.get_phase_status(target)
            
            for dep_phase in dependencies:
                if dep_phase not in phase_status:
                    self.logger.warning(f"فاز وابسته {dep_phase} برای فاز {phase_number} اجرا نشده")
                    return False
                
                if phase_status[dep_phase]['status'] != 'completed':
                    self.logger.warning(f"فاز وابسته {dep_phase} برای فاز {phase_number} تکمیل نشده")
                    return False
            
            return True
            
        except Exception as e:
            self.logger.error(f"خطا در اعتبارسنجی وابستگی‌های فاز {phase_number}: {e}")
            return False
    
    async def cleanup(self):
        """پاکسازی منابع فازها"""
        try:
            for phase_number, phase_class in self.phases.items():
                phase_instance = phase_class(self.config, self.db, self.api_manager)
                if hasattr(phase_instance, 'cleanup'):
                    await phase_instance.cleanup()
            
            self.logger.info("فازها پاکسازی شدند")
            
        except Exception as e:
            self.logger.error(f"خطا در پاکسازی فازها: {e}")


class BasePhase:
    """کلاس پایه برای فازها"""
    
    name = "Base Phase"
    description = "فاز پایه"
    dependencies = []
    parallel_safe = True
    
    def __init__(self, config, database, api_manager):
        self.config = config
        self.db = database
        self.api_manager = api_manager
        self.logger = logging.getLogger(f'arat.phase_{self.__class__.__name__.lower()}')
    
    async def initialize(self):
        """مقداردهی اولیه فاز"""
        pass
    
    async def run(self, target: str, **kwargs) -> Dict[str, Any]:
        """اجرای فاز"""
        raise NotImplementedError("تابع run باید پیاده‌سازی شود")
    
    async def cleanup(self):
        """پاکسازی منابع فاز"""
        pass
    
    async def validate_target(self, target: str) -> bool:
        """اعتبارسنجی هدف"""
        import re
        
        # الگوهای مختلف برای هدف
        patterns = [
            r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$',  # domain
            r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$',  # IPv4
            r'^[0-9a-fA-F]{1,4}(:[0-9a-fA-F]{1,4}){7}$',  # IPv6
            r'^[0-9a-fA-F]{1,4}(:[0-9a-fA-F]{1,4}){0,7}::[0-9a-fA-F]{1,4}(:[0-9a-fA-F]{1,4}){0,7}$'  # IPv6 compressed
        ]
        
        return any(re.match(pattern, target) for pattern in patterns)
    
    async def get_previous_results(self, target: str, phase_number: int) -> Dict[str, Any]:
        """دریافت نتایج فاز قبلی"""
        try:
            target_id = await self.db.get_target_id(target)
            if not target_id:
                return {}
            
            with self.db.get_session() as session:
                from core.database import PhaseResult
                
                phase_result = session.query(PhaseResult).filter(
                    PhaseResult.target_id == target_id,
                    PhaseResult.phase_number == phase_number,
                    PhaseResult.status == 'completed'
                ).first()
                
                if phase_result and phase_result.results_json:
                    return phase_result.results_json
                
                return {}
                
        except Exception as e:
            self.logger.error(f"خطا در دریافت نتایج فاز {phase_number}: {e}")
            return {}
    
    async def save_results(self, target: str, results: Dict[str, Any]):
        """ذخیره نتایج فاز"""
        try:
            phase_number = int(self.__class__.__name__.replace('Phase', ''))
            await self.db.save_phase_results(target, phase_number, results)
            
        except Exception as e:
            self.logger.error(f"خطا در ذخیره نتایج: {e}")
    
    def create_progress_callback(self, total: int):
        """ایجاد callback برای پیشرفت"""
        from tqdm import tqdm
        
        progress_bar = tqdm(total=total, desc=f"{self.name}", unit="item")
        
        def callback(completed: int = 1):
            progress_bar.update(completed)
        
        return callback, progress_bar