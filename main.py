#!/usr/bin/env python3
"""
Advanced Reconnaissance Tool - ARAT
یک ابزار جامع و پیشرفته برای reconnaissance و security assessment
"""

import asyncio
import sys
import os
from pathlib import Path
from typing import Dict, List, Optional, Any
import argparse
import logging
from datetime import datetime

# اضافه کردن مسیر پروژه به Python path
sys.path.append(str(Path(__file__).parent))

from core.config import Config
from core.logger import setup_logger
from core.database import Database
from core.api_manager import APIManager
from phases.phase_manager import PhaseManager
from web.panel import WebPanel
from utils.helpers import print_banner, validate_target


class ARAT:
    """کلاس اصلی ابزار ARAT"""
    
    def __init__(self, config_path: Optional[str] = None):
        self.config = Config(config_path)
        self.logger = setup_logger(self.config.log_level)
        self.db = Database(self.config.database_url)
        self.api_manager = APIManager(self.config)
        self.phase_manager = PhaseManager(self.config, self.db, self.api_manager)
        self.web_panel = None
        
    async def initialize(self):
        """مقداردهی اولیه ابزار"""
        try:
            self.logger.info("🚀 شروع مقداردهی ARAT...")
            
            # اتصال به دیتابیس
            await self.db.connect()
            self.logger.info("✅ اتصال به دیتابیس برقرار شد")
            
            # بارگذاری API keys
            await self.api_manager.load_api_keys()
            self.logger.info("✅ API keys بارگذاری شدند")
            
            # مقداردهی فازها
            await self.phase_manager.initialize()
            self.logger.info("✅ فازها مقداردهی شدند")
            
            self.logger.info("🎉 مقداردهی ARAT با موفقیت انجام شد")
            
        except Exception as e:
            self.logger.error(f"❌ خطا در مقداردهی: {e}")
            raise
    
    async def run_phase(self, phase_number: int, target: str, **kwargs) -> Dict[str, Any]:
        """اجرای یک فاز مشخص"""
        try:
            self.logger.info(f"🎯 شروع فاز {phase_number} برای هدف: {target}")
            
            result = await self.phase_manager.run_phase(phase_number, target, **kwargs)
            
            self.logger.info(f"✅ فاز {phase_number} با موفقیت تکمیل شد")
            return result
            
        except Exception as e:
            self.logger.error(f"❌ خطا در فاز {phase_number}: {e}")
            raise
    
    async def run_all_phases(self, target: str, **kwargs) -> Dict[str, Any]:
        """اجرای تمامی فازها"""
        try:
            self.logger.info(f"🎯 شروع reconnaissance کامل برای هدف: {target}")
            
            results = {}
            
            for phase_num in range(1, 11):
                try:
                    phase_result = await self.run_phase(phase_num, target, **kwargs)
                    results[f"phase_{phase_num}"] = phase_result
                    
                    # ذخیره نتایج فاز برای استفاده در فازهای بعدی
                    await self.db.save_phase_results(target, phase_num, phase_result)
                    
                except Exception as e:
                    self.logger.error(f"❌ خطا در فاز {phase_num}: {e}")
                    results[f"phase_{phase_num}"] = {"error": str(e)}
                    continue
            
            # تولید گزارش نهایی
            final_report = await self.generate_final_report(target, results)
            results["final_report"] = final_report
            
            self.logger.info(f"🎉 reconnaissance کامل برای {target} تکمیل شد")
            return results
            
        except Exception as e:
            self.logger.error(f"❌ خطا در reconnaissance کامل: {e}")
            raise
    
    async def generate_final_report(self, target: str, results: Dict[str, Any]) -> Dict[str, Any]:
        """تولید گزارش نهایی"""
        try:
            self.logger.info("📊 تولید گزارش نهایی...")
            
            report = {
                "target": target,
                "timestamp": datetime.now().isoformat(),
                "summary": {
                    "total_phases": len(results),
                    "successful_phases": len([r for r in results.values() if "error" not in r]),
                    "failed_phases": len([r for r in results.values() if "error" in r])
                },
                "phases": results,
                "recommendations": await self.generate_recommendations(results)
            }
            
            # ذخیره گزارش در دیتابیس
            await self.db.save_final_report(target, report)
            
            # تولید گزارش بصری
            await self.generate_visual_report(target, report)
            
            self.logger.info("✅ گزارش نهایی تولید شد")
            return report
            
        except Exception as e:
            self.logger.error(f"❌ خطا در تولید گزارش نهایی: {e}")
            raise
    
    async def generate_recommendations(self, results: Dict[str, Any]) -> List[str]:
        """تولید توصیه‌های امنیتی"""
        recommendations = []
        
        # تحلیل نتایج و تولید توصیه‌ها
        for phase_name, phase_result in results.items():
            if "error" in phase_result:
                continue
                
            # مثال: اگر ساب‌دامین‌های زیادی پیدا شد
            if phase_name == "phase_2" and "subdomains" in phase_result:
                subdomain_count = len(phase_result["subdomains"])
                if subdomain_count > 100:
                    recommendations.append(
                        f"تعداد زیاد ساب‌دامین ({subdomain_count}) - بررسی امنیتی تمامی ساب‌دامین‌ها توصیه می‌شود"
                    )
            
            # مثال: اگر آسیب‌پذیری‌هایی پیدا شد
            if phase_name == "phase_10" and "vulnerabilities" in phase_result:
                vuln_count = len(phase_result["vulnerabilities"])
                if vuln_count > 0:
                    recommendations.append(
                        f"تعداد {vuln_count} آسیب‌پذیری پیدا شد - رفع فوری توصیه می‌شود"
                    )
        
        return recommendations
    
    async def generate_visual_report(self, target: str, report: Dict[str, Any]):
        """تولید گزارش بصری"""
        try:
            from utils.report_generator import VisualReportGenerator
            
            generator = VisualReportGenerator(self.config)
            await generator.generate_html_report(target, report)
            
            self.logger.info("✅ گزارش بصری HTML تولید شد")
            
        except Exception as e:
            self.logger.error(f"❌ خطا در تولید گزارش بصری: {e}")
    
    def start_web_panel(self, host: str = "0.0.0.0", port: int = 8080):
        """شروع پنل وب"""
        try:
            self.logger.info(f"🌐 شروع پنل وب روی {host}:{port}")
            
            self.web_panel = WebPanel(self.config, self.db, self.phase_manager)
            self.web_panel.start(host, port)
            
        except Exception as e:
            self.logger.error(f"❌ خطا در شروع پنل وب: {e}")
            raise
    
    async def cleanup(self):
        """پاکسازی منابع"""
        try:
            self.logger.info("🧹 شروع پاکسازی منابع...")
            
            if self.web_panel:
                await self.web_panel.stop()
            
            await self.db.disconnect()
            
            self.logger.info("✅ پاکسازی منابع تکمیل شد")
            
        except Exception as e:
            self.logger.error(f"❌ خطا در پاکسازی: {e}")


async def main():
    """تابع اصلی"""
    parser = argparse.ArgumentParser(
        description="ARAT - Advanced Reconnaissance Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
مثال‌های استفاده:
  python main.py --target example.com --phase 1
  python main.py --target example.com --all-phases
  python main.py --web-panel --port 8080
  python main.py --config config.json --target example.com --phase 2
        """
    )
    
    parser.add_argument("--target", "-t", help="هدف برای reconnaissance")
    parser.add_argument("--phase", "-p", type=int, help="شماره فاز برای اجرا (1-10)")
    parser.add_argument("--all-phases", "-a", action="store_true", help="اجرای تمامی فازها")
    parser.add_argument("--web-panel", "-w", action="store_true", help="شروع پنل وب")
    parser.add_argument("--config", "-c", help="مسیر فایل تنظیمات")
    parser.add_argument("--port", type=int, default=8080, help="پورت پنل وب")
    parser.add_argument("--host", default="0.0.0.0", help="هاست پنل وب")
    parser.add_argument("--verbose", "-v", action="store_true", help="نمایش جزئیات بیشتر")
    
    args = parser.parse_args()
    
    # نمایش بنر
    print_banner()
    
    # ایجاد نمونه ARAT
    arat = ARAT(args.config)
    
    try:
        # مقداردهی اولیه
        await arat.initialize()
        
        if args.web_panel:
            # شروع پنل وب
            arat.start_web_panel(args.host, args.port)
            
        elif args.target:
            # اعتبارسنجی هدف
            if not validate_target(args.target):
                print("❌ هدف نامعتبر است")
                sys.exit(1)
            
            if args.phase:
                # اجرای فاز مشخص
                result = await arat.run_phase(args.phase, args.target)
                print(f"✅ فاز {args.phase} تکمیل شد")
                
            elif args.all_phases:
                # اجرای تمامی فازها
                results = await arat.run_all_phases(args.target)
                print("✅ تمامی فازها تکمیل شدند")
                
            else:
                print("❌ لطفاً فاز یا --all-phases را مشخص کنید")
                sys.exit(1)
        
        else:
            print("❌ لطفاً هدف را مشخص کنید یا از --web-panel استفاده کنید")
            sys.exit(1)
    
    except KeyboardInterrupt:
        print("\n⏹️  عملیات توسط کاربر متوقف شد")
        
    except Exception as e:
        print(f"❌ خطا: {e}")
        sys.exit(1)
        
    finally:
        await arat.cleanup()


if __name__ == "__main__":
    asyncio.run(main())