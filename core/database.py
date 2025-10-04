"""
مدیریت دیتابیس برای ARAT
"""

import asyncio
import json
from datetime import datetime
from typing import Dict, List, Any, Optional, Union
from pathlib import Path
import sqlite3
import aiosqlite
from sqlalchemy import create_engine, MetaData, Table, Column, Integer, String, Text, DateTime, Boolean, Float, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.dialects.mysql import LONGTEXT
import uuid
import logging


Base = declarative_base()


class Target(Base):
    """جدول اهداف"""
    __tablename__ = 'targets'
    
    id = Column(Integer, primary_key=True)
    uuid = Column(String(36), unique=True, nullable=False)
    domain = Column(String(255), nullable=False, index=True)
    ip_address = Column(String(45), index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    status = Column(String(50), default='pending')
    metadata_json = Column(JSON)


class Subdomain(Base):
    """جدول ساب‌دامین‌ها"""
    __tablename__ = 'subdomains'
    
    id = Column(Integer, primary_key=True)
    target_id = Column(Integer, nullable=False, index=True)
    subdomain = Column(String(255), nullable=False, index=True)
    ip_address = Column(String(45), index=True)
    status = Column(String(20), default='unknown')  # alive, dead, unknown
    http_status = Column(Integer)
    https_status = Column(Integer)
    title = Column(Text)
    server = Column(String(255))
    technology = Column(JSON)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    source = Column(String(100))  # shodan, virustotal, etc.
    verified = Column(Boolean, default=False)


class Port(Base):
    """جدول پورت‌ها"""
    __tablename__ = 'ports'
    
    id = Column(Integer, primary_key=True)
    target_id = Column(Integer, nullable=False, index=True)
    subdomain_id = Column(Integer, index=True)
    ip_address = Column(String(45), nullable=False, index=True)
    port = Column(Integer, nullable=False)
    protocol = Column(String(10), default='tcp')
    service = Column(String(100))
    version = Column(String(255))
    banner = Column(Text)
    state = Column(String(20), default='open')  # open, closed, filtered
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class Technology(Base):
    """جدول تکنولوژی‌ها"""
    __tablename__ = 'technologies'
    
    id = Column(Integer, primary_key=True)
    target_id = Column(Integer, nullable=False, index=True)
    subdomain_id = Column(Integer, index=True)
    technology = Column(String(255), nullable=False, index=True)
    version = Column(String(100))
    confidence = Column(Float, default=0.0)
    category = Column(String(100))  # cms, framework, server, etc.
    source = Column(String(100))  # header, content, js, etc.
    created_at = Column(DateTime, default=datetime.utcnow)


class Directory(Base):
    """جدول دایرکتوری‌ها"""
    __tablename__ = 'directories'
    
    id = Column(Integer, primary_key=True)
    target_id = Column(Integer, nullable=False, index=True)
    subdomain_id = Column(Integer, index=True)
    path = Column(String(500), nullable=False)
    status_code = Column(Integer)
    content_length = Column(Integer)
    content_type = Column(String(100))
    title = Column(Text)
    server = Column(String(255))
    technology = Column(JSON)
    created_at = Column(DateTime, default=datetime.utcnow)
    source = Column(String(100))


class Parameter(Base):
    """جدول پارامترها"""
    __tablename__ = 'parameters'
    
    id = Column(Integer, primary_key=True)
    target_id = Column(Integer, nullable=False, index=True)
    subdomain_id = Column(Integer, index=True)
    parameter = Column(String(255), nullable=False, index=True)
    value = Column(Text)
    source = Column(String(100))  # js, form, url, etc.
    method = Column(String(10))  # GET, POST, PUT, etc.
    created_at = Column(DateTime, default=datetime.utcnow)


class Endpoint(Base):
    """جدول endpoint ها"""
    __tablename__ = 'endpoints'
    
    id = Column(Integer, primary_key=True)
    target_id = Column(Integer, nullable=False, index=True)
    subdomain_id = Column(Integer, index=True)
    endpoint = Column(String(500), nullable=False)
    method = Column(String(10), nullable=False)
    status_code = Column(Integer)
    response_time = Column(Float)
    content_length = Column(Integer)
    content_type = Column(String(100))
    headers = Column(JSON)
    body = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    source = Column(String(100))


class Vulnerability(Base):
    """جدول آسیب‌پذیری‌ها"""
    __tablename__ = 'vulnerabilities'
    
    id = Column(Integer, primary_key=True)
    target_id = Column(Integer, nullable=False, index=True)
    subdomain_id = Column(Integer, index=True)
    vulnerability = Column(String(255), nullable=False)
    severity = Column(String(20))  # critical, high, medium, low, info
    description = Column(Text)
    solution = Column(Text)
    references = Column(JSON)
    verified = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)


class PhaseResult(Base):
    """جدول نتایج فازها"""
    __tablename__ = 'phase_results'
    
    id = Column(Integer, primary_key=True)
    target_id = Column(Integer, nullable=False, index=True)
    phase_number = Column(Integer, nullable=False, index=True)
    status = Column(String(20), default='running')  # running, completed, failed
    start_time = Column(DateTime, default=datetime.utcnow)
    end_time = Column(DateTime)
    duration = Column(Float)
    results_json = Column(JSON)
    error_message = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)


class Report(Base):
    """جدول گزارش‌ها"""
    __tablename__ = 'reports'
    
    id = Column(Integer, primary_key=True)
    target_id = Column(Integer, nullable=False, index=True)
    report_type = Column(String(50), nullable=False)  # final, phase, custom
    title = Column(String(255))
    content = Column(Text)
    format = Column(String(20), default='json')  # json, html, pdf
    file_path = Column(String(500))
    created_at = Column(DateTime, default=datetime.utcnow)


class APILog(Base):
    """جدول لاگ‌های API"""
    __tablename__ = 'api_logs'
    
    id = Column(Integer, primary_key=True)
    service = Column(String(100), nullable=False, index=True)
    endpoint = Column(String(500))
    method = Column(String(10))
    status_code = Column(Integer)
    response_time = Column(Float)
    error_message = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)


class Database:
    """کلاس مدیریت دیتابیس"""
    
    def __init__(self, database_url: str):
        self.database_url = database_url
        self.engine = None
        self.SessionLocal = None
        self.logger = logging.getLogger('arat.database')
    
    async def connect(self):
        """اتصال به دیتابیس"""
        try:
            self.logger.info(f"اتصال به دیتابیس: {self.database_url}")
            
            # ایجاد engine
            self.engine = create_engine(
                self.database_url,
                echo=False,
                pool_pre_ping=True,
                pool_recycle=3600
            )
            
            # ایجاد SessionLocal
            self.SessionLocal = sessionmaker(
                autocommit=False,
                autoflush=False,
                bind=self.engine
            )
            
            # ایجاد جداول
            await self.create_tables()
            
            self.logger.info("اتصال به دیتابیس برقرار شد")
            
        except Exception as e:
            self.logger.error(f"خطا در اتصال به دیتابیس: {e}")
            raise
    
    async def create_tables(self):
        """ایجاد جداول"""
        try:
            Base.metadata.create_all(bind=self.engine)
            self.logger.info("جداول دیتابیس ایجاد شدند")
        except Exception as e:
            self.logger.error(f"خطا در ایجاد جداول: {e}")
            raise
    
    async def disconnect(self):
        """قطع اتصال از دیتابیس"""
        try:
            if self.engine:
                self.engine.dispose()
            self.logger.info("اتصال به دیتابیس قطع شد")
        except Exception as e:
            self.logger.error(f"خطا در قطع اتصال: {e}")
    
    def get_session(self) -> Session:
        """دریافت session"""
        if not self.SessionLocal:
            raise RuntimeError("دیتابیس مقداردهی نشده است")
        return self.SessionLocal()
    
    async def save_target(self, domain: str, ip_address: str = None, metadata: Dict = None) -> int:
        """ذخیره هدف جدید"""
        try:
            with self.get_session() as session:
                # بررسی وجود هدف
                existing_target = session.query(Target).filter(Target.domain == domain).first()
                
                if existing_target:
                    self.logger.info(f"هدف {domain} قبلاً وجود دارد")
                    return existing_target.id
                
                # ایجاد هدف جدید
                target = Target(
                    uuid=str(uuid.uuid4()),
                    domain=domain,
                    ip_address=ip_address,
                    metadata_json=metadata or {}
                )
                
                session.add(target)
                session.commit()
                session.refresh(target)
                
                self.logger.info(f"هدف جدید ذخیره شد: {domain} (ID: {target.id})")
                return target.id
                
        except Exception as e:
            self.logger.error(f"خطا در ذخیره هدف: {e}")
            raise
    
    async def save_subdomain(self, target_id: int, subdomain: str, **kwargs) -> int:
        """ذخیره ساب‌دامین"""
        try:
            with self.get_session() as session:
                # بررسی وجود ساب‌دامین
                existing = session.query(Subdomain).filter(
                    Subdomain.target_id == target_id,
                    Subdomain.subdomain == subdomain
                ).first()
                
                if existing:
                    # به‌روزرسانی اطلاعات موجود
                    for key, value in kwargs.items():
                        if hasattr(existing, key):
                            setattr(existing, key, value)
                    existing.updated_at = datetime.utcnow()
                    session.commit()
                    return existing.id
                
                # ایجاد ساب‌دامین جدید
                subdomain_obj = Subdomain(
                    target_id=target_id,
                    subdomain=subdomain,
                    **kwargs
                )
                
                session.add(subdomain_obj)
                session.commit()
                session.refresh(subdomain_obj)
                
                self.logger.debug(f"ساب‌دامین ذخیره شد: {subdomain}")
                return subdomain_obj.id
                
        except Exception as e:
            self.logger.error(f"خطا در ذخیره ساب‌دامین: {e}")
            raise
    
    async def save_port(self, target_id: int, ip_address: str, port: int, **kwargs) -> int:
        """ذخیره پورت"""
        try:
            with self.get_session() as session:
                # بررسی وجود پورت
                existing = session.query(Port).filter(
                    Port.target_id == target_id,
                    Port.ip_address == ip_address,
                    Port.port == port
                ).first()
                
                if existing:
                    # به‌روزرسانی اطلاعات موجود
                    for key, value in kwargs.items():
                        if hasattr(existing, key):
                            setattr(existing, key, value)
                    existing.updated_at = datetime.utcnow()
                    session.commit()
                    return existing.id
                
                # ایجاد پورت جدید
                port_obj = Port(
                    target_id=target_id,
                    ip_address=ip_address,
                    port=port,
                    **kwargs
                )
                
                session.add(port_obj)
                session.commit()
                session.refresh(port_obj)
                
                self.logger.debug(f"پورت ذخیره شد: {ip_address}:{port}")
                return port_obj.id
                
        except Exception as e:
            self.logger.error(f"خطا در ذخیره پورت: {e}")
            raise
    
    async def save_technology(self, target_id: int, technology: str, **kwargs) -> int:
        """ذخیره تکنولوژی"""
        try:
            with self.get_session() as session:
                # بررسی وجود تکنولوژی
                existing = session.query(Technology).filter(
                    Technology.target_id == target_id,
                    Technology.technology == technology
                ).first()
                
                if existing:
                    return existing.id
                
                # ایجاد تکنولوژی جدید
                tech_obj = Technology(
                    target_id=target_id,
                    technology=technology,
                    **kwargs
                )
                
                session.add(tech_obj)
                session.commit()
                session.refresh(tech_obj)
                
                self.logger.debug(f"تکنولوژی ذخیره شد: {technology}")
                return tech_obj.id
                
        except Exception as e:
            self.logger.error(f"خطا در ذخیره تکنولوژی: {e}")
            raise
    
    async def save_directory(self, target_id: int, path: str, **kwargs) -> int:
        """ذخیره دایرکتوری"""
        try:
            with self.get_session() as session:
                # بررسی وجود دایرکتوری
                existing = session.query(Directory).filter(
                    Directory.target_id == target_id,
                    Directory.path == path
                ).first()
                
                if existing:
                    return existing.id
                
                # ایجاد دایرکتوری جدید
                dir_obj = Directory(
                    target_id=target_id,
                    path=path,
                    **kwargs
                )
                
                session.add(dir_obj)
                session.commit()
                session.refresh(dir_obj)
                
                self.logger.debug(f"دایرکتوری ذخیره شد: {path}")
                return dir_obj.id
                
        except Exception as e:
            self.logger.error(f"خطا در ذخیره دایرکتوری: {e}")
            raise
    
    async def save_parameter(self, target_id: int, parameter: str, **kwargs) -> int:
        """ذخیره پارامتر"""
        try:
            with self.get_session() as session:
                # بررسی وجود پارامتر
                existing = session.query(Parameter).filter(
                    Parameter.target_id == target_id,
                    Parameter.parameter == parameter
                ).first()
                
                if existing:
                    return existing.id
                
                # ایجاد پارامتر جدید
                param_obj = Parameter(
                    target_id=target_id,
                    parameter=parameter,
                    **kwargs
                )
                
                session.add(param_obj)
                session.commit()
                session.refresh(param_obj)
                
                self.logger.debug(f"پارامتر ذخیره شد: {parameter}")
                return param_obj.id
                
        except Exception as e:
            self.logger.error(f"خطا در ذخیره پارامتر: {e}")
            raise
    
    async def save_endpoint(self, target_id: int, endpoint: str, method: str, **kwargs) -> int:
        """ذخیره endpoint"""
        try:
            with self.get_session() as session:
                # بررسی وجود endpoint
                existing = session.query(Endpoint).filter(
                    Endpoint.target_id == target_id,
                    Endpoint.endpoint == endpoint,
                    Endpoint.method == method
                ).first()
                
                if existing:
                    return existing.id
                
                # ایجاد endpoint جدید
                endpoint_obj = Endpoint(
                    target_id=target_id,
                    endpoint=endpoint,
                    method=method,
                    **kwargs
                )
                
                session.add(endpoint_obj)
                session.commit()
                session.refresh(endpoint_obj)
                
                self.logger.debug(f"Endpoint ذخیره شد: {method} {endpoint}")
                return endpoint_obj.id
                
        except Exception as e:
            self.logger.error(f"خطا در ذخیره endpoint: {e}")
            raise
    
    async def save_vulnerability(self, target_id: int, vulnerability: str, **kwargs) -> int:
        """ذخیره آسیب‌پذیری"""
        try:
            with self.get_session() as session:
                # بررسی وجود آسیب‌پذیری
                existing = session.query(Vulnerability).filter(
                    Vulnerability.target_id == target_id,
                    Vulnerability.vulnerability == vulnerability
                ).first()
                
                if existing:
                    return existing.id
                
                # ایجاد آسیب‌پذیری جدید
                vuln_obj = Vulnerability(
                    target_id=target_id,
                    vulnerability=vulnerability,
                    **kwargs
                )
                
                session.add(vuln_obj)
                session.commit()
                session.refresh(vuln_obj)
                
                self.logger.info(f"آسیب‌پذیری ذخیره شد: {vulnerability}")
                return vuln_obj.id
                
        except Exception as e:
            self.logger.error(f"خطا در ذخیره آسیب‌پذیری: {e}")
            raise
    
    async def save_phase_results(self, target: str, phase_number: int, results: Dict[str, Any]) -> int:
        """ذخیره نتایج فاز"""
        try:
            # دریافت target_id
            target_id = await self.get_target_id(target)
            
            with self.get_session() as session:
                # بررسی وجود نتیجه فاز
                existing = session.query(PhaseResult).filter(
                    PhaseResult.target_id == target_id,
                    PhaseResult.phase_number == phase_number
                ).first()
                
                if existing:
                    # به‌روزرسانی نتیجه موجود
                    existing.status = 'completed'
                    existing.end_time = datetime.utcnow()
                    existing.duration = (existing.end_time - existing.start_time).total_seconds()
                    existing.results_json = results
                    session.commit()
                    return existing.id
                
                # ایجاد نتیجه جدید
                phase_result = PhaseResult(
                    target_id=target_id,
                    phase_number=phase_number,
                    status='completed',
                    end_time=datetime.utcnow(),
                    results_json=results
                )
                
                session.add(phase_result)
                session.commit()
                session.refresh(phase_result)
                
                self.logger.info(f"نتایج فاز {phase_number} ذخیره شد")
                return phase_result.id
                
        except Exception as e:
            self.logger.error(f"خطا در ذخیره نتایج فاز: {e}")
            raise
    
    async def save_final_report(self, target: str, report: Dict[str, Any]) -> int:
        """ذخیره گزارش نهایی"""
        try:
            # دریافت target_id
            target_id = await self.get_target_id(target)
            
            with self.get_session() as session:
                report_obj = Report(
                    target_id=target_id,
                    report_type='final',
                    title=f"گزارش نهایی {target}",
                    content=json.dumps(report, ensure_ascii=False, indent=2),
                    format='json'
                )
                
                session.add(report_obj)
                session.commit()
                session.refresh(report_obj)
                
                self.logger.info(f"گزارش نهایی برای {target} ذخیره شد")
                return report_obj.id
                
        except Exception as e:
            self.logger.error(f"خطا در ذخیره گزارش نهایی: {e}")
            raise
    
    async def get_target_id(self, domain: str) -> Optional[int]:
        """دریافت ID هدف"""
        try:
            with self.get_session() as session:
                target = session.query(Target).filter(Target.domain == domain).first()
                return target.id if target else None
        except Exception as e:
            self.logger.error(f"خطا در دریافت target_id: {e}")
            return None
    
    async def get_subdomains(self, target_id: int) -> List[Dict[str, Any]]:
        """دریافت ساب‌دامین‌ها"""
        try:
            with self.get_session() as session:
                subdomains = session.query(Subdomain).filter(
                    Subdomain.target_id == target_id
                ).all()
                
                return [
                    {
                        'id': sub.id,
                        'subdomain': sub.subdomain,
                        'ip_address': sub.ip_address,
                        'status': sub.status,
                        'http_status': sub.http_status,
                        'https_status': sub.https_status,
                        'title': sub.title,
                        'server': sub.server,
                        'technology': sub.technology,
                        'source': sub.source,
                        'verified': sub.verified,
                        'created_at': sub.created_at.isoformat() if sub.created_at else None
                    }
                    for sub in subdomains
                ]
        except Exception as e:
            self.logger.error(f"خطا در دریافت ساب‌دامین‌ها: {e}")
            return []
    
    async def get_ports(self, target_id: int) -> List[Dict[str, Any]]:
        """دریافت پورت‌ها"""
        try:
            with self.get_session() as session:
                ports = session.query(Port).filter(
                    Port.target_id == target_id
                ).all()
                
                return [
                    {
                        'id': port.id,
                        'ip_address': port.ip_address,
                        'port': port.port,
                        'protocol': port.protocol,
                        'service': port.service,
                        'version': port.version,
                        'banner': port.banner,
                        'state': port.state,
                        'created_at': port.created_at.isoformat() if port.created_at else None
                    }
                    for port in ports
                ]
        except Exception as e:
            self.logger.error(f"خطا در دریافت پورت‌ها: {e}")
            return []
    
    async def get_technologies(self, target_id: int) -> List[Dict[str, Any]]:
        """دریافت تکنولوژی‌ها"""
        try:
            with self.get_session() as session:
                technologies = session.query(Technology).filter(
                    Technology.target_id == target_id
                ).all()
                
                return [
                    {
                        'id': tech.id,
                        'technology': tech.technology,
                        'version': tech.version,
                        'confidence': tech.confidence,
                        'category': tech.category,
                        'source': tech.source,
                        'created_at': tech.created_at.isoformat() if tech.created_at else None
                    }
                    for tech in technologies
                ]
        except Exception as e:
            self.logger.error(f"خطا در دریافت تکنولوژی‌ها: {e}")
            return []
    
    async def get_directories(self, target_id: int) -> List[Dict[str, Any]]:
        """دریافت دایرکتوری‌ها"""
        try:
            with self.get_session() as session:
                directories = session.query(Directory).filter(
                    Directory.target_id == target_id
                ).all()
                
                return [
                    {
                        'id': dir.id,
                        'path': dir.path,
                        'status_code': dir.status_code,
                        'content_length': dir.content_length,
                        'content_type': dir.content_type,
                        'title': dir.title,
                        'server': dir.server,
                        'technology': dir.technology,
                        'source': dir.source,
                        'created_at': dir.created_at.isoformat() if dir.created_at else None
                    }
                    for dir in directories
                ]
        except Exception as e:
            self.logger.error(f"خطا در دریافت دایرکتوری‌ها: {e}")
            return []
    
    async def get_parameters(self, target_id: int) -> List[Dict[str, Any]]:
        """دریافت پارامترها"""
        try:
            with self.get_session() as session:
                parameters = session.query(Parameter).filter(
                    Parameter.target_id == target_id
                ).all()
                
                return [
                    {
                        'id': param.id,
                        'parameter': param.parameter,
                        'value': param.value,
                        'source': param.source,
                        'method': param.method,
                        'created_at': param.created_at.isoformat() if param.created_at else None
                    }
                    for param in parameters
                ]
        except Exception as e:
            self.logger.error(f"خطا در دریافت پارامترها: {e}")
            return []
    
    async def get_endpoints(self, target_id: int) -> List[Dict[str, Any]]:
        """دریافت endpoint ها"""
        try:
            with self.get_session() as session:
                endpoints = session.query(Endpoint).filter(
                    Endpoint.target_id == target_id
                ).all()
                
                return [
                    {
                        'id': endpoint.id,
                        'endpoint': endpoint.endpoint,
                        'method': endpoint.method,
                        'status_code': endpoint.status_code,
                        'response_time': endpoint.response_time,
                        'content_length': endpoint.content_length,
                        'content_type': endpoint.content_type,
                        'headers': endpoint.headers,
                        'body': endpoint.body,
                        'source': endpoint.source,
                        'created_at': endpoint.created_at.isoformat() if endpoint.created_at else None
                    }
                    for endpoint in endpoints
                ]
        except Exception as e:
            self.logger.error(f"خطا در دریافت endpoint ها: {e}")
            return []
    
    async def get_vulnerabilities(self, target_id: int) -> List[Dict[str, Any]]:
        """دریافت آسیب‌پذیری‌ها"""
        try:
            with self.get_session() as session:
                vulnerabilities = session.query(Vulnerability).filter(
                    Vulnerability.target_id == target_id
                ).all()
                
                return [
                    {
                        'id': vuln.id,
                        'vulnerability': vuln.vulnerability,
                        'severity': vuln.severity,
                        'description': vuln.description,
                        'solution': vuln.solution,
                        'references': vuln.references,
                        'verified': vuln.verified,
                        'created_at': vuln.created_at.isoformat() if vuln.created_at else None
                    }
                    for vuln in vulnerabilities
                ]
        except Exception as e:
            self.logger.error(f"خطا در دریافت آسیب‌پذیری‌ها: {e}")
            return []
    
    async def get_target_summary(self, domain: str) -> Dict[str, Any]:
        """دریافت خلاصه هدف"""
        try:
            target_id = await self.get_target_id(domain)
            if not target_id:
                return {}
            
            subdomains = await self.get_subdomains(target_id)
            ports = await self.get_ports(target_id)
            technologies = await self.get_technologies(target_id)
            directories = await self.get_directories(target_id)
            parameters = await self.get_parameters(target_id)
            endpoints = await self.get_endpoints(target_id)
            vulnerabilities = await self.get_vulnerabilities(target_id)
            
            return {
                'target_id': target_id,
                'subdomains_count': len(subdomains),
                'ports_count': len(ports),
                'technologies_count': len(technologies),
                'directories_count': len(directories),
                'parameters_count': len(parameters),
                'endpoints_count': len(endpoints),
                'vulnerabilities_count': len(vulnerabilities),
                'alive_subdomains': len([s for s in subdomains if s['status'] == 'alive']),
                'open_ports': len([p for p in ports if p['state'] == 'open']),
                'verified_vulnerabilities': len([v for v in vulnerabilities if v['verified']])
            }
        except Exception as e:
            self.logger.error(f"خطا در دریافت خلاصه هدف: {e}")
            return {}
    
    async def log_api_call(self, service: str, endpoint: str = None, method: str = None, 
                          status_code: int = None, response_time: float = None, 
                          error_message: str = None):
        """ثبت لاگ API call"""
        try:
            with self.get_session() as session:
                api_log = APILog(
                    service=service,
                    endpoint=endpoint,
                    method=method,
                    status_code=status_code,
                    response_time=response_time,
                    error_message=error_message
                )
                
                session.add(api_log)
                session.commit()
                
        except Exception as e:
            self.logger.error(f"خطا در ثبت لاگ API: {e}")
    
    async def cleanup_old_data(self, days: int = 30):
        """پاکسازی داده‌های قدیمی"""
        try:
            cutoff_date = datetime.utcnow() - timedelta(days=days)
            
            with self.get_session() as session:
                # حذف لاگ‌های API قدیمی
                session.query(APILog).filter(
                    APILog.created_at < cutoff_date
                ).delete()
                
                session.commit()
                
            self.logger.info(f"داده‌های قدیمی‌تر از {days} روز پاک شدند")
            
        except Exception as e:
            self.logger.error(f"خطا در پاکسازی داده‌های قدیمی: {e}")
    
    async def backup_database(self, backup_path: str):
        """پشتیبان‌گیری از دیتابیس"""
        try:
            # برای SQLite
            if self.database_url.startswith('sqlite'):
                import shutil
                shutil.copy2(self.database_url.replace('sqlite:///', ''), backup_path)
                self.logger.info(f"پشتیبان‌گیری در {backup_path} انجام شد")
            else:
                self.logger.warning("پشتیبان‌گیری فقط برای SQLite پشتیبانی می‌شود")
                
        except Exception as e:
            self.logger.error(f"خطا در پشتیبان‌گیری: {e}")