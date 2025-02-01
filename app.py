import streamlit as st
import sqlite3
import hashlib
import pandas as pd
from datetime import datetime,timedelta
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os
from typing import Optional, List, Dict, Any
import logging
import redis
import ipaddress
import jwt
import random
import time
import yaml

class DatabaseManager:
    def __init__(self, db_path: str = "students_management.db"):
        """Initialize database connection and create tables if they don't exist."""
        self.db_path = db_path
        self.create_tables()
    
    def get_connection(self) -> sqlite3.Connection:
        """Create and return a database connection."""
        return sqlite3.connect(self.db_path)
    
    def create_tables(self):
        """Create all necessary database tables."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Create Students table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS students (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    phone TEXT,
                    programme_id INTEGER,
                    level TEXT,
                    status TEXT DEFAULT 'active',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (programme_id) REFERENCES programmes (id)
                )
            ''')
            
            # Create Programmes table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS programmes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    description TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Create Programme_Levels table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS programme_levels (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    programme_id INTEGER,
                    level_name TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (programme_id) REFERENCES programmes (id)
                )
            ''')
            
            # Create Documents table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS documents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    student_id INTEGER,
                    document_type TEXT NOT NULL,
                    file_path TEXT NOT NULL,
                    status TEXT DEFAULT 'pending',
                    admin_feedback TEXT,
                    uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (student_id) REFERENCES students (id)
                )
            ''')
            
            # Create Administrators table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS administrators (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    role TEXT NOT NULL,
                    password_hash TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Create Audit_Logs table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    admin_id INTEGER,
                    action TEXT NOT NULL,
                    description TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (admin_id) REFERENCES administrators (id)
                )
            ''')
            
            # Create Events table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    description TEXT,
                    date TIMESTAMP NOT NULL,
                    programme_id INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (programme_id) REFERENCES programmes (id)
                )
            ''')
            
            # Create Emails table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS emails (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    recipient_id INTEGER,
                    email_subject TEXT NOT NULL,
                    email_body TEXT NOT NULL,
                    sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    status TEXT DEFAULT 'pending',
                    FOREIGN KEY (recipient_id) REFERENCES students (id)
                )
            ''')
            
            conn.commit()
            
            
            
            
            
class SecurityEnhancements:
    def __init__(self):
        """Initialize security settings and Redis connection."""
        self.max_login_attempts = 3
        self.session_timeout = 30  # minutes
        self.jwt_secret = "your-secret-key"  # Store this in environment variables
        self.redis_client = redis.Redis(host='localhost', port=6379, db=0)
        
        # Configure logging
        logging.basicConfig(
            filename='security.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )

    def generate_jwt_token(self, user_id: int, user_type: str) -> str:
        """Generate JWT token for authenticated users."""
        payload = {
            'user_id': user_id,
            'user_type': user_type,
            'exp': datetime.utcnow() + timedelta(minutes=self.session_timeout)
        }
        return jwt.encode(payload, self.jwt_secret, algorithm='HS256')

    def verify_jwt_token(self, token: str) -> Optional[Dict]:
        """Verify JWT token and return payload if valid."""
        try:
            payload = jwt.decode(token, self.jwt_secret, algorithms=['HS256'])
            return payload
        except jwt.ExpiredSignatureError:
            logging.warning(f"Expired token attempted to be used")
            return None
        except jwt.InvalidTokenError:
            logging.warning(f"Invalid token attempted to be used")
            return None

    def implement_2fa(self, user_email: str) -> str:
        """Implement Two-Factor Authentication."""
        # Generate OTP
        otp = ''.join(random.choices('0123456789', k=6))
        
        # Store OTP in Redis with 5-minute expiration
        self.redis_client.setex(
            f"2fa:{user_email}",
            300,  # 5 minutes expiration
            otp
        )
        
        # In production, use proper email service
        self._send_2fa_email(user_email, otp)
        
        return otp

    def verify_2fa(self, user_email: str, provided_otp: str) -> bool:
        """Verify the OTP provided by the user."""
        stored_otp = self.redis_client.get(f"2fa:{user_email}")
        if stored_otp and stored_otp.decode() == provided_otp:
            self.redis_client.delete(f"2fa:{user_email}")
            return True
        return False

    def rate_limit_check(self, ip_address: str) -> bool:
        """
        Implement rate limiting for API calls and login attempts.
        Returns True if request is allowed, False if rate limit exceeded.
        """
        try:
            # Validate IP address
            ipaddress.ip_address(ip_address)
            
            # Key for Redis
            key = f"ratelimit:{ip_address}"
            
            # Get current count
            count = self.redis_client.get(key)
            
            if count is None:
                # First request from this IP
                self.redis_client.setex(key, 60, 1)  # 1-minute window
                return True
            
            count = int(count)
            if count >= 100:  # 100 requests per minute limit
                logging.warning(f"Rate limit exceeded for IP: {ip_address}")
                return False
            
            self.redis_client.incr(key)
            return True
            
        except ValueError:
            logging.error(f"Invalid IP address: {ip_address}")
            return False

    def track_login_attempts(self, username: str, ip_address: str) -> bool:
        """
        Track failed login attempts and implement temporary lockout.
        Returns True if account is locked, False otherwise.
        """
        key = f"login_attempts:{username}"
        
        # Get current failed attempts
        attempts = self.redis_client.get(key)
        
        if attempts and int(attempts) >= self.max_login_attempts:
            logging.warning(f"Account locked due to multiple failed attempts: {username}")
            return True
        
        return False

    def record_failed_login(self, username: str, ip_address: str):
        """Record failed login attempt."""
        key = f"login_attempts:{username}"
        
        # Increment failed attempts counter
        self.redis_client.incr(key)
        
        # Set expiration for 30 minutes if not set
        if not self.redis_client.ttl(key):
            self.redis_client.expire(key, 1800)  # 30 minutes
        
        self.audit_trail(username, "failed_login", ip_address)

    def reset_login_attempts(self, username: str):
        """Reset failed login attempts counter after successful login."""
        key = f"login_attempts:{username}"
        self.redis_client.delete(key)

    def audit_trail(self, user_id: str, action: str, ip_address: str):
        """
        Enhanced audit logging with detailed information.
        """
        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'user_id': user_id,
            'action': action,
            'ip_address': ip_address,
            'user_agent': self._get_user_agent(),
            'geolocation': self._get_geolocation(ip_address)
        }
        
        # Log to file
        logging.info(f"Audit Trail: {log_entry}")
        
        # Store in database
        self._store_audit_log(log_entry)

    def password_policy_check(self, password: str) -> tuple[bool, str]:
        """
        Check if password meets security requirements.
        Returns (bool, str) tuple: (passes_check, error_message)
        """
        if len(password) < 12:
            return False, "Password must be at least 12 characters long"
        
        if not any(c.isupper() for c in password):
            return False, "Password must contain at least one uppercase letter"
            
        if not any(c.islower() for c in password):
            return False, "Password must contain at least one lowercase letter"
            
        if not any(c.isdigit() for c in password):
            return False, "Password must contain at least one number"
            
        if not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            return False, "Password must contain at least one special character"
            
        return True, "Password meets requirements"

    def _send_2fa_email(self, email: str, otp: str):
        """Send 2FA code via email."""
        # Implementation would depend on your email service
        # This is a placeholder for the actual implementation
        logging.info(f"2FA email sent to {email}")

    def _get_user_agent(self) -> str:
        """Get user agent information."""
        # Implementation would depend on your web framework
        return "User Agent Information"

    def _get_geolocation(self, ip_address: str) -> Dict:
        """Get geolocation information for IP address."""
        # Implementation would use a geolocation service
        return {"country": "Unknown", "city": "Unknown"}

    def _store_audit_log(self, log_entry: Dict):
        """Store audit log in database."""
        # Implementation would depend on your database structure
        pass

class SecurityMiddleware:
    """Middleware to handle security checks for each request."""
    
    def __init__(self, security: SecurityEnhancements):
        self.security = security

    def process_request(self, request, ip_address: str) -> bool:
        """
        Process each request for security checks.
        Returns True if request should be allowed, False otherwise.
        """
        # Check rate limiting
        if not self.security.rate_limit_check(ip_address):
            return False
        
        # Verify JWT token if present
        token = self._get_token_from_request(request)
        if token:
            payload = self.security.verify_jwt_token(token)
            if not payload:
                return False
        
        return True

    def _get_token_from_request(self, request) -> Optional[str]:
        """Extract JWT token from request."""
        # Implementation would depend on your web framework
        return None
      
import plotly.express as px
import plotly.graph_objects as go
from sklearn.linear_model import LinearRegression
from sklearn.model_selection import train_test_split

class AdvancedAnalytics:
    def __init__(self, db_manager):
        """Initialize analytics with database connection."""
        self.db_manager = db_manager

    def get_performance_metrics(self) -> Dict[str, Any]:
        """Generate comprehensive performance metrics."""
        metrics = {
            'student_metrics': self.calculate_student_metrics(),
            'document_metrics': self.calculate_document_metrics(),
            'programme_metrics': self.calculate_programme_metrics(),
            'verification_metrics': self.calculate_verification_metrics()
        }
        return metrics

    def calculate_student_metrics(self) -> Dict[str, Any]:
        """Calculate student-related metrics."""
        with self.db_manager.get_connection() as conn:
            # Total active students
            active_students = pd.read_sql(
                "SELECT COUNT(*) as count FROM students WHERE status = 'active'",
                conn
            ).iloc[0]['count']

            # New registrations in last 30 days
            new_students = pd.read_sql("""
                SELECT COUNT(*) as count 
                FROM students 
                WHERE created_at >= date('now', '-30 days')
            """, conn).iloc[0]['count']

            # Retention rate
            retention_rate = self.calculate_retention_rate(conn)

            return {
                'active_students': active_students,
                'new_registrations': new_students,
                'retention_rate': retention_rate,
                'growth_rate': self.calculate_growth_rate(conn)
            }

    def calculate_document_metrics(self) -> Dict[str, Any]:
        """Calculate document-related metrics."""
        with self.db_manager.get_connection() as conn:
            # Document statistics
            doc_stats = pd.read_sql("""
                SELECT 
                    status,
                    COUNT(*) as count,
                    AVG(JULIANDAY(COALESCE(verified_at, 'now')) - 
                        JULIANDAY(uploaded_at)) as avg_processing_time
                FROM documents
                GROUP BY status
            """, conn)

            return {
                'total_documents': doc_stats['count'].sum(),
                'pending_documents': doc_stats[doc_stats['status'] == 'pending']['count'].iloc[0],
                'avg_processing_time': doc_stats['avg_processing_time'].mean(),
                'verification_rate': self.calculate_verification_rate(conn)
            }

    def calculate_programme_metrics(self) -> Dict[str, Any]:
        """Calculate programme-related metrics."""
        with self.db_manager.get_connection() as conn:
            # Programme popularity
            programme_stats = pd.read_sql("""
                SELECT 
                    p.name,
                    COUNT(s.id) as student_count,
                    AVG(CASE WHEN s.status = 'active' THEN 1 ELSE 0 END) as retention_rate
                FROM programmes p
                LEFT JOIN students s ON p.id = s.programme_id
                GROUP BY p.id, p.name
            """, conn)

            return {
                'programme_popularity': programme_stats.to_dict('records'),
                'top_programmes': programme_stats.nlargest(3, 'student_count').to_dict('records'),
                'programme_growth': self.calculate_programme_growth(conn)
            }

    def generate_predictive_insights(self) -> Dict[str, Any]:
        """Generate predictive analytics for enrollment trends."""
        with self.db_manager.get_connection() as conn:
            # Get historical enrollment data
            enrollments = pd.read_sql("""
                SELECT DATE(created_at) as date, COUNT(*) as count
                FROM students
                GROUP BY DATE(created_at)
                ORDER BY date
            """, conn)

            # Prepare data for prediction
            enrollments['days_from_start'] = (
                pd.to_datetime(enrollments['date']) - 
                pd.to_datetime(enrollments['date'].min())
            ).dt.days

            X = enrollments[['days_from_start']]
            y = enrollments['count']

            # Train model
            model = LinearRegression()
            model.fit(X, y)

            # Predict next 30 days
            future_days = pd.DataFrame({
                'days_from_start': range(
                    enrollments['days_from_start'].max() + 1,
                    enrollments['days_from_start'].max() + 31
                )
            })
            predictions = model.predict(future_days)

            return {
                'predicted_enrollments': predictions.tolist(),
                'confidence_score': model.score(X, y),
                'trend': 'increasing' if model.coef_[0] > 0 else 'decreasing'
            }

    def create_custom_reports(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Generate customized reports based on parameters."""
        reports = {}
        
        if parameters.get('enrollment_trends'):
            reports['enrollment'] = self.generate_enrollment_report()
        
        if parameters.get('verification_efficiency'):
            reports['verification'] = self.generate_verification_report()
        
        if parameters.get('programme_performance'):
            reports['programme'] = self.generate_programme_report()
        
        return reports

    def generate_visualization(self, data_type: str) -> go.Figure:
        """Generate interactive visualizations using Plotly."""
        if data_type == 'enrollment_trends':
            return self._create_enrollment_visualization()
        elif data_type == 'programme_distribution':
            return self._create_programme_visualization()
        elif data_type == 'verification_metrics':
            return self._create_verification_visualization()
        
        raise ValueError(f"Unknown visualization type: {data_type}")

    def _create_enrollment_visualization(self) -> go.Figure:
        """Create enrollment trends visualization."""
        with self.db_manager.get_connection() as conn:
            data = pd.read_sql("""
                SELECT DATE(created_at) as date, COUNT(*) as count
                FROM students
                GROUP BY DATE(created_at)
                ORDER BY date
            """, conn)
            
            fig = px.line(
                data,
                x='date',
                y='count',
                title='Daily Enrollment Trends'
            )
            return fig

    def calculate_retention_rate(self, conn) -> float:
        """Calculate student retention rate."""
        retention_data = pd.read_sql("""
            SELECT 
                COUNT(CASE WHEN status = 'active' THEN 1 END) as active,
                COUNT(*) as total
            FROM students
            WHERE created_at <= date('now', '-30 days')
        """, conn)
        
        return (retention_data['active'] / retention_data['total']).iloc[0]

    def calculate_verification_rate(self, conn) -> float:
        """Calculate document verification rate."""
        verification_data = pd.read_sql("""
            SELECT 
                COUNT(CASE WHEN status = 'verified' THEN 1 END) as verified,
                COUNT(*) as total
            FROM documents
            WHERE uploaded_at >= date('now', '-7 days')
        """, conn)
        
        return (verification_data['verified'] / verification_data['total']).iloc[0]

      
import magic  # python-magic library for file type detection
import PyPDF2
from PIL import Image
import pytesseract
import hashlib
from pathlib import Path
import shutil
import logging
import clamd  # ClamAV antivirus integration
from pdf2image import convert_from_path

class EnhancedDocumentSystem:
    def __init__(self):
        """Initialize document management system."""
        self.allowed_formats = {
            'pdf': ['application/pdf'],
            'image': ['image/jpeg', 'image/png'],
            'doc': ['application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document']
        }
        self.max_file_size = 10 * 1024 * 1024  # 10MB
        self.storage_path = Path("document_storage")
        self.temp_path = Path("temp_storage")
        self.clamav = clamd.ClamdUnixSocket()
        
        # Create necessary directories
        self.storage_path.mkdir(exist_ok=True)
        self.temp_path.mkdir(exist_ok=True)
        
        # Configure logging
        logging.basicConfig(
            filename='document_system.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )

    def process_document(self, file_path: Path, document_type: str, user_id: int) -> Dict:
        """
        Process and store a new document.
        Returns document metadata including storage path and extracted text.
        """
        try:
            # Validate file
            self.validate_file(file_path)
            
            # Scan for viruses
            self.scan_document(file_path)
            
            # Generate unique filename
            unique_filename = self.generate_unique_filename(file_path, user_id)
            
            # Process and store document
            processed_path = self.storage_path / unique_filename
            
            # Compress if necessary
            if file_path.stat().st_size > self.max_file_size / 2:
                self.compress_document(file_path, processed_path)
            else:
                shutil.copy2(file_path, processed_path)
            
            # Extract text
            extracted_text = self.extract_text(processed_path)
            
            # Generate metadata
            metadata = {
                'original_filename': file_path.name,
                'stored_filename': unique_filename,
                'file_size': processed_path.stat().st_size,
                'mime_type': magic.from_file(str(processed_path), mime=True),
                'upload_date': datetime.now().isoformat(),
                'user_id': user_id,
                'document_type': document_type,
                'extracted_text': extracted_text,
                'checksum': self.calculate_checksum(processed_path)
            }
            
            # Store version information
            self.store_version_info(metadata)
            
            return metadata
            
        except Exception as e:
            logging.error(f"Error processing document: {str(e)}")
            raise

    def validate_file(self, file_path: Path) -> bool:
        """Validate file format and size."""
        if not file_path.exists():
            raise ValueError("File does not exist")
            
        file_size = file_path.stat().st_size
        if file_size > self.max_file_size:
            raise ValueError(f"File size exceeds maximum limit of {self.max_file_size/1024/1024}MB")
            
        mime_type = magic.from_file(str(file_path), mime=True)
        valid_formats = [fmt for formats in self.allowed_formats.values() for fmt in formats]
        if mime_type not in valid_formats:
            raise ValueError(f"Invalid file format: {mime_type}")
            
        return True

    def scan_document(self, file_path: Path) -> bool:
        """Scan document for viruses using ClamAV."""
        try:
            scan_result = self.clamav.scan(str(file_path))
            if scan_result[str(file_path)][0] == 'OK':
                return True
            else:
                raise ValueError("Virus detected in document")
        except Exception as e:
            logging.error(f"Virus scan failed: {str(e)}")
            raise

    def compress_document(self, input_path: Path, output_path: Path):
        """Compress document based on its type."""
        mime_type = magic.from_file(str(input_path), mime=True)
        
        if mime_type == 'application/pdf':
            self._compress_pdf(input_path, output_path)
        elif mime_type.startswith('image/'):
            self._compress_image(input_path, output_path)
        else:
            # For other formats, just copy the file
            shutil.copy2(input_path, output_path)

    def extract_text(self, file_path: Path) -> str:
        """Extract text content from document."""
        mime_type = magic.from_file(str(file_path), mime=True)
        
        if mime_type == 'application/pdf':
            return self._extract_text_from_pdf(file_path)
        elif mime_type.startswith('image/'):
            return self._extract_text_from_image(file_path)
        else:
            return ""

    def version_control(self, document_id: int) -> List[Dict]:
        """Track document versions."""
        versions = []
        version_path = self.storage_path / f"versions/{document_id}"
        if version_path.exists():
            for version_file in version_path.glob("*"):
                metadata = self._read_version_metadata(version_file)
                versions.append(metadata)
        return sorted(versions, key=lambda x: x['timestamp'])

    def _compress_pdf(self, input_path: Path, output_path: Path):
        """Compress PDF file."""
        reader = PyPDF2.PdfReader(str(input_path))
        writer = PyPDF2.PdfWriter()
        
        for page in reader.pages:
            page.compress_content_streams()
            writer.add_page(page)
            
        with open(output_path, 'wb') as f:
            writer.write(f)

    def _compress_image(self, input_path: Path, output_path: Path):
        """Compress image file."""
        img = Image.open(input_path)
        img.save(output_path, optimize=True, quality=85)

    def _extract_text_from_pdf(self, file_path: Path) -> str:
        """Extract text from PDF file."""
        text = ""
        pdf = PyPDF2.PdfReader(str(file_path))
        
        for page in pdf.pages:
            text += page.extract_text() + "\n"
            
        return text

    def _extract_text_from_image(self, file_path: Path) -> str:
        """Extract text from image using OCR."""
        img = Image.open(file_path)
        return pytesseract.image_to_string(img)

    def generate_unique_filename(self, original_path: Path, user_id: int) -> str:
        """Generate unique filename for storage."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        hash_value = hashlib.md5(f"{user_id}{timestamp}".encode()).hexdigest()[:8]
        return f"{user_id}_{timestamp}_{hash_value}{original_path.suffix}"

    def calculate_checksum(self, file_path: Path) -> str:
        """Calculate SHA-256 checksum of file."""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    def store_version_info(self, metadata: Dict):
        """Store version information for document."""
        version_path = self.storage_path / f"versions/{metadata['user_id']}"
        version_path.mkdir(parents=True, exist_ok=True)
        
        version_file = version_path / f"{metadata['stored_filename']}.json"
        with open(version_file, 'w') as f:
            json.dump(metadata, f)

    def _read_version_metadata(self, version_file: Path) -> Dict:
        """Read version metadata from file."""
        with open(version_file, 'r') as f:
            return json.load(f)
    
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from typing import List, Dict, Optional
from datetime import datetime, timedelta
import jinja2
import json
import logging
from pathlib import Path
import schedule
import threading
import time
import queue

class EnhancedCommunication:
    def __init__(self, email_config: Dict):
        """Initialize communication system with configuration."""
        self.email_config = email_config
        self.template_env = jinja2.Environment(
            loader=jinja2.FileSystemLoader('email_templates')
        )
        self.message_queue = queue.Queue()
        self.running = True
        
        # Start background worker
        self.worker_thread = threading.Thread(target=self._process_queue)
        self.worker_thread.start()
        
        # Configure logging
        logging.basicConfig(
            filename='communication.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )

    def schedule_notification(self, notification_data: Dict):
        """Schedule an automated notification."""
        schedule_time = notification_data.get('schedule_time')
        if schedule_time:
            schedule.every().day.at(schedule_time).do(
                self.send_notification,
                notification_data
            )

    def send_notification(self, notification_data: Dict):
        """Send a notification via email."""
        try:
            template = self.template_env.get_template(
                f"{notification_data['template_name']}.html"
            )
            
            html_content = template.render(**notification_data['template_data'])
            
            email_data = {
                'subject': notification_data['subject'],
                'body': html_content,
                'recipients': notification_data['recipients'],
                'attachments': notification_data.get('attachments', [])
            }
            
            self.message_queue.put(email_data)
            
            return True
        except Exception as e:
            logging.error(f"Failed to send notification: {str(e)}")
            return False

    def create_email_campaign(self, campaign_data: Dict):
        """Create and manage email campaigns."""
        try:
            # Validate campaign data
            self._validate_campaign_data(campaign_data)
            
            # Store campaign information
            campaign_id = self._store_campaign(campaign_data)
            
            # Schedule campaign emails
            for recipient in campaign_data['recipients']:
                email_data = {
                    'campaign_id': campaign_id,
                    'recipient': recipient,
                    'subject': campaign_data['subject'],
                    'template_name': campaign_data['template_name'],
                    'template_data': campaign_data['template_data']
                }
                
                if campaign_data.get('schedule_time'):
                    self.schedule_notification(email_data)
                else:
                    self.message_queue.put(email_data)
            
            return campaign_id
        except Exception as e:
            logging.error(f"Failed to create campaign: {str(e)}")
            raise

    def generate_template(self, template_type: str, data: Dict) -> str:
        """Generate email content from template."""
        try:
            template = self.template_env.get_template(f"{template_type}.html")
            return template.render(**data)
        except Exception as e:
            logging.error(f"Failed to generate template: {str(e)}")
            raise

    def _process_queue(self):
        """Process queued messages in background."""
        while self.running:
            try:
                while not self.message_queue.empty():
                    email_data = self.message_queue.get()
                    self._send_email(email_data)
                    self.message_queue.task_done()
                time.sleep(1)
            except Exception as e:
                logging.error(f"Error processing message queue: {str(e)}")

    def _send_email(self, email_data: Dict):
        """Send individual email."""
        try:
            msg = MIMEMultipart()
            msg['Subject'] = email_data['subject']
            msg['From'] = self.email_config['sender_email']
            msg['To'] = email_data['recipient']
            
            # Add HTML content
            msg.attach(MIMEText(email_data['body'], 'html'))
            
            # Add attachments if any
            for attachment in email_data.get('attachments', []):
                with open(attachment, 'rb') as f:
                    part = MIMEApplication(f.read(), Name=Path(attachment).name)
                    part['Content-Disposition'] = f'attachment; filename="{Path(attachment).name}"'
                    msg.attach(part)
            
            # Send email
            with smtplib.SMTP(self.email_config['smtp_server'], self.email_config['smtp_port']) as server:
                server.starttls()
                server.login(
                    self.email_config['sender_email'],
                    self.email_config['sender_password']
                )
                server.send_message(msg)
            
            self._log_email_sent(email_data)
            
        except Exception as e:
            logging.error(f"Failed to send email: {str(e)}")
            self._log_email_error(email_data, str(e))
            raise

    def _validate_campaign_data(self, campaign_data: Dict):
        """Validate campaign data structure."""
        required_fields = ['subject', 'template_name', 'recipients', 'template_data']
        for field in required_fields:
            if field not in campaign_data:
                raise ValueError(f"Missing required field: {field}")

    def _store_campaign(self, campaign_data: Dict) -> int:
        """Store campaign information and return campaign ID."""
        # Implementation depends on your storage system
        pass

    def _log_email_sent(self, email_data: Dict):
        """Log successful email sending."""
        logging.info(f"Email sent successfully: {json.dumps(email_data)}")

    def _log_email_error(self, email_data: Dict, error: str):
        """Log email sending error."""
        logging.error(f"Email sending failed: {error}, Data: {json.dumps(email_data)}")

    def cleanup(self):
        """Cleanup resources before shutdown."""
        self.running = False
        self.worker_thread.join()
    
from datetime import datetime
import json
from typing import Dict, List, Optional, Union
import logging
from enum import Enum
import nltk
from nltk.tokenize import word_tokenize
from nltk.corpus import stopwords
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
import pandas as pd

class TicketStatus(Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    CLOSED = "closed"

class TicketPriority(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    URGENT = "urgent"

class StudentSupport:
    def __init__(self, db_manager):
        """Initialize student support system."""
        self.db_manager = db_manager
        self.support_categories = ['technical', 'academic', 'administrative', 'financial']
        
        # Initialize NLTK components
        nltk.download('punkt')
        nltk.download('stopwords')
        nltk.download('wordnet')
        
        # Load FAQ database
        self.faq_db = self._load_faq_database()
        self.vectorizer = TfidfVectorizer()
        self.faq_vectors = self.vectorizer.fit_transform(self.faq_db['question'])
        
        # Configure logging
        logging.basicConfig(
            filename='support.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )

    def create_support_ticket(self, 
                            student_id: int, 
                            category: str, 
                            subject: str,
                            description: str,
                            priority: TicketPriority = TicketPriority.MEDIUM) -> Dict:
        """Create and track support tickets."""
        try:
            if category not in self.support_categories:
                raise ValueError(f"Invalid category. Must be one of {self.support_categories}")

            ticket_data = {
                'student_id': student_id,
                'category': category,
                'subject': subject,
                'description': description,
                'priority': priority.value,
                'status': TicketStatus.OPEN.value,
                'created_at': datetime.now().isoformat(),
                'updated_at': datetime.now().isoformat(),
                'assigned_to': None,
                'resolution': None
            }

            ticket_id = self._store_ticket(ticket_data)
            
            # Auto-assign ticket based on category and priority
            self._auto_assign_ticket(ticket_id, category, priority)
            
            # Send confirmation email to student
            self._send_ticket_confirmation(student_id, ticket_id)
            
            # Check if automated resolution is possible
            self._attempt_auto_resolution(ticket_id, description)
            
            return {'ticket_id': ticket_id, **ticket_data}

        except Exception as e:
            logging.error(f"Error creating support ticket: {str(e)}")
            raise

    def update_ticket_status(self, 
                           ticket_id: int, 
                           status: TicketStatus,
                           resolution: Optional[str] = None,
                           admin_id: Optional[int] = None) -> Dict:
        """Update the status of a support ticket."""
        try:
            update_data = {
                'status': status.value,
                'updated_at': datetime.now().isoformat()
            }
            
            if resolution:
                update_data['resolution'] = resolution
            
            if admin_id:
                update_data['admin_id'] = admin_id
            
            self._update_ticket(ticket_id, update_data)
            
            # Notify student of status change
            self._notify_ticket_update(ticket_id, status)
            
            return self.get_ticket_details(ticket_id)

        except Exception as e:
            logging.error(f"Error updating ticket status: {str(e)}")
            raise

    def chatbot_support(self, query: str) -> Dict[str, Union[str, float]]:
        """AI-powered chatbot for common queries."""
        try:
            # Preprocess query
            processed_query = self._preprocess_text(query)
            
            # Vectorize query
            query_vector = self.vectorizer.transform([processed_query])
            
            # Calculate similarity with FAQ database
            similarities = cosine_similarity(query_vector, self.faq_vectors)
            
            # Get most similar FAQ
            best_match_idx = similarities.argmax()
            similarity_score = similarities[0][best_match_idx]
            
            if similarity_score > 0.7:  # Confidence threshold
                response = {
                    'answer': self.faq_db.iloc[best_match_idx]['answer'],
                    'confidence': float(similarity_score),
                    'needs_human': False
                }
            else:
                response = {
                    'answer': "I'm not quite sure about this. Would you like me to create a support ticket for you?",
                    'confidence': float(similarity_score),
                    'needs_human': True
                }
            
            return response

        except Exception as e:
            logging.error(f"Chatbot error: {str(e)}")
            return {
                'answer': "I'm having trouble processing your request. Please try again later.",
                'confidence': 0.0,
                'needs_human': True
            }

    def knowledge_base(self, category: Optional[str] = None) -> List[Dict]:
        """Access to FAQ and help documents."""
        try:
            if category:
                return self._get_category_articles(category)
            return self._get_all_articles()

        except Exception as e:
            logging.error(f"Error accessing knowledge base: {str(e)}")
            raise

    def get_ticket_details(self, ticket_id: int) -> Dict:
        """Retrieve detailed information about a specific ticket."""
        try:
            with self.db_manager.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT * FROM support_tickets 
                    WHERE id = ?
                """, (ticket_id,))
                ticket = cursor.fetchone()
                
                if not ticket:
                    raise ValueError(f"Ticket {ticket_id} not found")
                
                return dict(ticket)

        except Exception as e:
            logging.error(f"Error retrieving ticket details: {str(e)}")
            raise

    def _store_ticket(self, ticket_data: Dict) -> int:
        """Store ticket in database and return ticket ID."""
        try:
            with self.db_manager.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO support_tickets 
                    (student_id, category, subject, description, priority, status, 
                     created_at, updated_at, assigned_to, resolution)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    ticket_data['student_id'],
                    ticket_data['category'],
                    ticket_data['subject'],
                    ticket_data['description'],
                    ticket_data['priority'],
                    ticket_data['status'],
                    ticket_data['created_at'],
                    ticket_data['updated_at'],
                    ticket_data['assigned_to'],
                    ticket_data['resolution']
                ))
                return cursor.lastrowid

        except Exception as e:
            logging.error(f"Error storing ticket: {str(e)}")
            raise

    def _load_faq_database(self) -> pd.DataFrame:
        """Load FAQ database from JSON file."""
        try:
            with open('faq_database.json', 'r') as f:
                faq_data = json.load(f)
            return pd.DataFrame(faq_data)

        except Exception as e:
            logging.error(f"Error loading FAQ database: {str(e)}")
            return pd.DataFrame(columns=['question', 'answer', 'category'])

    def _preprocess_text(self, text: str) -> str:
        """Preprocess text for NLP operations."""
        # Tokenize
        tokens = word_tokenize(text.lower())
        
        # Remove stopwords
        stop_words = set(stopwords.words('english'))
        tokens = [token for token in tokens if token not in stop_words]
        
        return ' '.join(tokens)

    def _auto_assign_ticket(self, ticket_id: int, category: str, priority: TicketPriority):
        """Automatically assign ticket to appropriate staff member."""
        # Implementation depends on your staff management system
        pass

    def _send_ticket_confirmation(self, student_id: int, ticket_id: int):
        """Send confirmation email to student."""
        # Implementation depends on your email system
        pass

    def _notify_ticket_update(self, ticket_id: int, status: TicketStatus):
        """Notify relevant parties of ticket updates."""
        # Implementation depends on your notification system
        pass

    def _attempt_auto_resolution(self, ticket_id: int, description: str):
        """Attempt to automatically resolve ticket using chatbot."""
        response = self.chatbot_support(description)
        if not response['needs_human'] and response['confidence'] > 0.9:
            self.update_ticket_status(
                ticket_id,
                TicketStatus.RESOLVED,
                resolution=response['answer']
            )

    def _get_category_articles(self, category: str) -> List[Dict]:
        """Retrieve knowledge base articles for a specific category."""
        try:
            with self.db_manager.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT * FROM knowledge_base 
                    WHERE category = ?
                    ORDER BY created_at DESC
                """, (category,))
                return [dict(row) for row in cursor.fetchall()]

        except Exception as e:
            logging.error(f"Error retrieving category articles: {str(e)}")
            raise

    def _get_all_articles(self) -> List[Dict]:
        """Retrieve all knowledge base articles."""
        try:
            with self.db_manager.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT * FROM knowledge_base 
                    ORDER BY category, created_at DESC
                """)
                return [dict(row) for row in cursor.fetchall()]

        except Exception as e:
            logging.error(f"Error retrieving all articles: {str(e)}")
            raise
    
from decimal import Decimal
from typing import Dict, List, Optional
import stripe
from datetime import datetime
import logging
import json
from enum import Enum

class PaymentStatus(Enum):
    PENDING = "pending"
    COMPLETED = "completed"
    FAILED = "failed"
    REFUNDED = "refunded"

class PaymentMethod(Enum):
    CARD = "card"
    BANK_TRANSFER = "bank_transfer"
    MOBILE_MONEY = "mobile_money"

class PaymentSystem:
    def __init__(self, config: Dict):
        """Initialize payment system with configuration."""
        self.config = config
        stripe.api_key = config['stripe_secret_key']
        
        # Configure logging
        logging.basicConfig(
            filename='payments.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )

    def process_payment(self, 
                       student_id: int, 
                       amount: Decimal, 
                       payment_method: PaymentMethod,
                       description: str,
                       metadata: Optional[Dict] = None) -> Dict:
        """Process student payments."""
        try:
            # Validate amount
            if amount <= 0:
                raise ValueError("Amount must be greater than 0")

            payment_data = {
                'student_id': student_id,
                'amount': amount,
                'payment_method': payment_method.value,
                'description': description,
                'status': PaymentStatus.PENDING.value,
                'created_at': datetime.now().isoformat(),
                'metadata': metadata or {}
            }

            # Process payment based on method
            if payment_method == PaymentMethod.CARD:
                result = self._process_card_payment(payment_data)
            elif payment_method == PaymentMethod.BANK_TRANSFER:
                result = self._process_bank_transfer(payment_data)
            elif payment_method == PaymentMethod.MOBILE_MONEY:
                result = self._process_mobile_money(payment_data)
            else:
                raise ValueError(f"Unsupported payment method: {payment_method}")

            # Store payment record
            payment_id = self._store_payment(result)
            
            # Generate receipt
            receipt_url = self.generate_receipt(payment_id)
            
            # Send confirmation
            self._send_payment_confirmation(student_id, payment_id)
            
            return {
                'payment_id': payment_id,
                'status': result['status'],
                'receipt_url': receipt_url,
                **result
            }

        except Exception as e:
            logging.error(f"Payment processing error: {str(e)}")
            self._handle_payment_error(student_id, amount, str(e))
            raise

    def generate_receipt(self, payment_id: int) -> str:
        """Generate payment receipt."""
        try:
            # Get payment details
            payment_details = self._get_payment_details(payment_id)
            
            # Generate PDF receipt
            receipt_path = self._generate_pdf_receipt(payment_details)
            
            # Store receipt in system
            receipt_url = self._store_receipt(payment_id, receipt_path)
            
            return receipt_url

        except Exception as e:
            logging.error(f"Receipt generation error: {str(e)}")
            raise

    def process_refund(self, 
                      payment_id: int, 
                      amount: Optional[Decimal] = None,
                      reason: str = "") -> Dict:
        """Process refund for a payment."""
        try:
            payment_details = self._get_payment_details(payment_id)
            
            if payment_details['status'] != PaymentStatus.COMPLETED.value:
                raise ValueError("Can only refund completed payments")

            refund_amount = amount or payment_details['amount']
            
            if refund_amount > payment_details['amount']:
                raise ValueError("Refund amount cannot exceed original payment amount")

            # Process refund based on original payment method
            if payment_details['payment_method'] == PaymentMethod.CARD.value:
                refund_result = self._process_card_refund(payment_details, refund_amount)
            else:
                refund_result = self._process_manual_refund(payment_details, refund_amount)

            # Update payment status
            self._update_payment_status(payment_id, PaymentStatus.REFUNDED)
            
            # Store refund record
            refund_id = self._store_refund(payment_id, refund_result)
            
            # Notify student
            self._send_refund_notification(payment_details['student_id'], refund_id)
            
            return refund_result

        except Exception as e:
            logging.error(f"Refund processing error: {str(e)}")
            raise

    def payment_reminder(self, student_id: int, payment_type: str):
        """Send payment reminders."""
        try:
            # Get pending payments
            pending_payments = self._get_pending_payments(student_id)
            
            if pending_payments:
                # Generate reminder message
                reminder = self._generate_payment_reminder(student_id, pending_payments)
                
                # Send reminder
                self._send_reminder_notification(student_id, reminder)
                
                # Log reminder
                self._log_payment_reminder(student_id, pending_payments)

        except Exception as e:
            logging.error(f"Payment reminder error: {str(e)}")
            raise

    def _process_card_payment(self, payment_data: Dict) -> Dict:
        """Process card payment using Stripe."""
        try:
            payment_intent = stripe.PaymentIntent.create(
                amount=int(payment_data['amount'] * 100),  # Convert to cents
                currency='usd',
                payment_method_types=['card'],
                metadata={
                    'student_id': str(payment_data['student_id']),
                    'description': payment_data['description']
                }
            )
            
            return {
                'transaction_id': payment_intent.id,
                'status': PaymentStatus.COMPLETED.value,
                'processor_response': payment_intent
            }

        except stripe.error.StripeError as e:
            logging.error(f"Stripe payment error: {str(e)}")
            raise

    def _process_bank_transfer(self, payment_data: Dict) -> Dict:
        """Process bank transfer payment."""
        # Implementation depends on your bank integration
        pass

    def _process_mobile_money(self, payment_data: Dict) -> Dict:
        """Process mobile money payment."""
        # Implementation depends on your mobile money integration
        pass

    def _store_payment(self, payment_result: Dict) -> int:
        """Store payment record in database."""
        try:
            with self.db_manager.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO payments 
                    (student_id, amount, payment_method, description, status,
                     transaction_id, processor_response, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    payment_result['student_id'],
                    payment_result['amount'],
                    payment_result['payment_method'],
                    payment_result['description'],
                    payment_result['status'],
                    payment_result['transaction_id'],
                    json.dumps(payment_result['processor_response']),
                    datetime.now().isoformat()
                ))
                return cursor.lastrowid

        except Exception as e:
            logging.error(f"Error storing payment: {str(e)}")
            raise

    def _generate_pdf_receipt(self, payment_details: Dict) -> str:
        """Generate PDF receipt from payment details."""
        # Implementation for PDF generation
        pass

    def _send_payment_confirmation(self, student_id: int, payment_id: int):
        """Send payment confirmation to student."""
        # Implementation for sending confirmation
        pass

    def _handle_payment_error(self, student_id: int, amount: Decimal, error: str):
        """Handle payment processing errors."""
        # Implementation for error handling
        pass
    
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Union
import icalendar
import pytz
from enum import Enum
import logging
import json
from dateutil.rrule import rrule, DAILY, WEEKLY, MONTHLY

class EventType(Enum):
    LECTURE = "lecture"
    EXAM = "exam"
    DEADLINE = "deadline"
    WORKSHOP = "workshop"
    HOLIDAY = "holiday"

class EventRecurrence(Enum):
    NONE = "none"
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"

class SchedulingSystem:
    def __init__(self, db_manager):
        """Initialize scheduling system."""
        self.db_manager = db_manager
        self.timezone = pytz.UTC
        
        # Configure logging
        logging.basicConfig(
            filename='scheduling.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )

    def create_event(self,
                    title: str,
                    start_time: datetime,
                    end_time: datetime,
                    event_type: EventType,
                    description: str = "",
                    location: str = "",
                    programme_id: Optional[int] = None,
                    recurrence: EventRecurrence = EventRecurrence.NONE,
                    recurrence_end: Optional[datetime] = None,
                    max_participants: Optional[int] = None) -> Dict:
        """Create a new calendar event."""
        try:
            # Validate event times
            if start_time >= end_time:
                raise ValueError("End time must be after start time")

            event_data = {
                'title': title,
                'start_time': start_time.astimezone(self.timezone),
                'end_time': end_time.astimezone(self.timezone),
                'event_type': event_type.value,
                'description': description,
                'location': location,
                'programme_id': programme_id,
                'recurrence': recurrence.value,
                'recurrence_end': recurrence_end,
                'max_participants': max_participants,
                'created_at': datetime.now(self.timezone)
            }

            # Check for scheduling conflicts
            if self._check_conflicts(event_data):
                raise ValueError("Event conflicts with existing schedule")

            # Create event and get ID
            event_id = self._store_event(event_data)

            # Generate recurring events if applicable
            if recurrence != EventRecurrence.NONE:
                self._create_recurring_events(event_id, event_data)

            # Send notifications to affected students
            self._notify_event_creation(event_id, event_data)

            return {'event_id': event_id, **event_data}

        except Exception as e:
            logging.error(f"Error creating event: {str(e)}")
            raise

    def update_event(self, event_id: int, updates: Dict) -> Dict:
        """Update an existing event."""
        try:
            current_event = self._get_event(event_id)
            if not current_event:
                raise ValueError(f"Event {event_id} not found")

            # Update event data
            update_data = {**current_event, **updates}
            
            # Check for conflicts with updated time if applicable
            if 'start_time' in updates or 'end_time' in updates:
                if self._check_conflicts(update_data, exclude_event_id=event_id):
                    raise ValueError("Updated event conflicts with existing schedule")

            # Update the event
            self._update_event_record(event_id, update_data)

            # Update recurring events if applicable
            if current_event['recurrence'] != EventRecurrence.NONE.value:
                self._update_recurring_events(event_id, update_data)

            # Notify affected participants
            self._notify_event_update(event_id, update_data)

            return self._get_event(event_id)

        except Exception as e:
            logging.error(f"Error updating event: {str(e)}")
            raise

    def delete_event(self, event_id: int, delete_series: bool = False) -> bool:
        """Delete an event or series of events."""
        try:
            event = self._get_event(event_id)
            if not event:
                raise ValueError(f"Event {event_id} not found")

            if delete_series and event['recurrence'] != EventRecurrence.NONE.value:
                self._delete_event_series(event_id)
            else:
                self._delete_single_event(event_id)

            # Notify affected participants
            self._notify_event_deletion(event)

            return True

        except Exception as e:
            logging.error(f"Error deleting event: {str(e)}")
            raise

    def get_calendar(self,
                    start_date: datetime,
                    end_date: datetime,
                    programme_id: Optional[int] = None,
                    event_type: Optional[EventType] = None) -> List[Dict]:
        """Get calendar events for a specific period."""
        try:
            events = self._fetch_events(start_date, end_date, programme_id, event_type)
            return self._format_events(events)

        except Exception as e:
            logging.error(f"Error fetching calendar: {str(e)}")
            raise

    def export_calendar(self,
                       start_date: datetime,
                       end_date: datetime,
                       format: str = 'ical',
                       programme_id: Optional[int] = None) -> Union[str, bytes]:
        """Export calendar in various formats."""
        try:
            events = self._fetch_events(start_date, end_date, programme_id)
            
            if format.lower() == 'ical':
                return self._export_to_ical(events)
            elif format.lower() == 'json':
                return self._export_to_json(events)
            else:
                raise ValueError(f"Unsupported export format: {format}")

        except Exception as e:
            logging.error(f"Error exporting calendar: {str(e)}")
            raise

    def set_reminder(self,
                    event_id: int,
                    reminder_time: timedelta,
                    reminder_type: str = 'email') -> Dict:
        """Set a reminder for an event."""
        try:
            event = self._get_event(event_id)
            if not event:
                raise ValueError(f"Event {event_id} not found")

            reminder_data = {
                'event_id': event_id,
                'reminder_time': reminder_time,
                'reminder_type': reminder_type,
                'created_at': datetime.now(self.timezone)
            }

            reminder_id = self._store_reminder(reminder_data)
            return {'reminder_id': reminder_id, **reminder_data}

        except Exception as e:
            logging.error(f"Error setting reminder: {str(e)}")
            raise

    def _store_event(self, event_data: Dict) -> int:
        """Store event in database."""
        try:
            with self.db_manager.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO events 
                    (title, start_time, end_time, event_type, description,
                     location, programme_id, recurrence, recurrence_end,
                     max_participants, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    event_data['title'],
                    event_data['start_time'].isoformat(),
                    event_data['end_time'].isoformat(),
                    event_data['event_type'],
                    event_data['description'],
                    event_data['location'],
                    event_data['programme_id'],
                    event_data['recurrence'],
                    event_data['recurrence_end'].isoformat() if event_data['recurrence_end'] else None,
                    event_data['max_participants'],
                    event_data['created_at'].isoformat()
                ))
                return cursor.lastrowid

        except Exception as e:
            logging.error(f"Error storing event: {str(e)}")
            raise

    def _check_conflicts(self, event_data: Dict, exclude_event_id: Optional[int] = None) -> bool:
        """Check for scheduling conflicts."""
        try:
            with self.db_manager.get_connection() as conn:
                cursor = conn.cursor()
                query = """
                    SELECT COUNT(*) FROM events
                    WHERE programme_id = ? 
                    AND ((start_time BETWEEN ? AND ?) 
                    OR (end_time BETWEEN ? AND ?))
                """
                params = [
                    event_data['programme_id'],
                    event_data['start_time'].isoformat(),
                    event_data['end_time'].isoformat(),
                    event_data['start_time'].isoformat(),
                    event_data['end_time'].isoformat()
                ]

                if exclude_event_id:
                    query += " AND id != ?"
                    params.append(exclude_event_id)

                cursor.execute(query, params)
                count = cursor.fetchone()[0]
                return count > 0

        except Exception as e:
            logging.error(f"Error checking conflicts: {str(e)}")
            raise

    def _create_recurring_events(self, parent_id: int, event_data: Dict):
        """Create recurring events based on recurrence pattern."""
        try:
            freq = getattr(rrule, event_data['recurrence'].upper())
            
            # Generate recurrence dates
            dates = list(rrule(
                freq,
                dtstart=event_data['start_time'],
                until=event_data['recurrence_end']
            ))

            # Create events for each date
            for date in dates[1:]:  # Skip first date (already created)
                delta = date - event_data['start_time']
                recurring_event = {
                    **event_data,
                    'start_time': event_data['start_time'] + delta,
                    'end_time': event_data['end_time'] + delta,
                    'parent_event_id': parent_id
                }
                self._store_event(recurring_event)

        except Exception as e:
            logging.error(f"Error creating recurring events: {str(e)}")
            raise

    def _export_to_ical(self, events: List[Dict]) -> bytes:
        """Export events to iCalendar format."""
        try:
            cal = icalendar.Calendar()
            cal.add('prodid', '-//Student Management System//EN')
            cal.add('version', '2.0')

            for event in events:
                ical_event = icalendar.Event()
                ical_event.add('summary', event['title'])
                ical_event.add('dtstart', event['start_time'])
                ical_event.add('dtend', event['end_time'])
                ical_event.add('description', event['description'])
                ical_event.add('location', event['location'])
                cal.add_component(ical_event)

            return cal.to_ical()

        except Exception as e:
            logging.error(f"Error exporting to iCal: {str(e)}")
            raise

    def _notify_event_creation(self, event_id: int, event_data: Dict):
        """Notify relevant parties about new event."""
        # Implementation for notification system
        pass

    def _notify_event_update(self, event_id: int, event_data: Dict):
        """Notify relevant parties about event updates."""
        # Implementation for notification system
        pass

    def _notify_event_deletion(self, event_data: Dict):
        """Notify relevant parties about event deletion."""
        # Implementation for notification system
        pass
    
from typing import Dict, List, Optional
import jwt
import requests
import json
import logging
from datetime import datetime, timedelta
from enum import Enum

class NotificationType(Enum):
    INFO = "info"
    WARNING = "warning"
    URGENT = "urgent"

class MobileIntegration:
    def __init__(self, config: Dict):
        """Initialize mobile integration system."""
        self.config = config
        self.fcm_url = "https://fcm.googleapis.com/fcm/send"
        self.api_key = config['fcm_api_key']
        
        # Configure logging
        logging.basicConfig(
            filename='mobile_integration.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )

    def register_device(self, user_id: int, device_token: str, platform: str) -> Dict:
        """Register a mobile device for push notifications."""
        try:
            device_data = {
                'user_id': user_id,
                'device_token': device_token,
                'platform': platform,
                'registered_at': datetime.now().isoformat()
            }

            device_id = self._store_device(device_data)
            return {'device_id': device_id, **device_data}

        except Exception as e:
            logging.error(f"Error registering device: {str(e)}")
            raise

    def send_push_notification(self,
                             user_ids: List[int],
                             title: str,
                             message: str,
                             notification_type: NotificationType = NotificationType.INFO,
                             data: Optional[Dict] = None) -> Dict:
        """Send push notification to specified users."""
        try:
            # Get device tokens for users
            device_tokens = self._get_device_tokens(user_ids)
            
            if not device_tokens:
                raise ValueError("No registered devices found for specified users")

            notification_data = {
                'notification': {
                    'title': title,
                    'body': message,
                    'click_action': 'FLUTTER_NOTIFICATION_CLICK',
                    'priority': 'high' if notification_type == NotificationType.URGENT else 'normal'
                },
                'data': data or {},
                'registration_ids': device_tokens
            }

            # Send to FCM
            response = self._send_fcm_notification(notification_data)
            
            # Store notification record
            notification_id = self._store_notification({
                'user_ids': user_ids,
                'title': title,
                'message': message,
                'type': notification_type.value,
                'data': data,
                'sent_at': datetime.now().isoformat(),
                'fcm_response': response
            })

            return {
                'notification_id': notification_id,
                'success': response['success'],
                'failure': response['failure']
            }

        except Exception as e:
            logging.error(f"Error sending push notification: {str(e)}")
            raise

    def sync_data(self, user_id: int, last_sync: datetime) -> Dict:
        """Sync data between web and mobile platforms."""
        try:
            # Get updates since last sync
            updates = {
                'profile': self._get_profile_updates(user_id, last_sync),
                'calendar': self._get_calendar_updates(user_id, last_sync),
                'documents': self._get_document_updates(user_id, last_sync),
                'notifications': self._get_notification_updates(user_id, last_sync)
            }

            # Record sync
            sync_id = self._record_sync(user_id, updates)

            return {
                'sync_id': sync_id,
                'sync_time': datetime.now().isoformat(),
                'updates': updates
            }

        except Exception as e:
            logging.error(f"Error syncing data: {str(e)}")
            raise

    def generate_mobile_token(self, user_id: int) -> str:
        """Generate JWT token for mobile app authentication."""
        try:
            payload = {
                'user_id': user_id,
                'exp': datetime.utcnow() + timedelta(days=30),
                'iat': datetime.utcnow()
            }
            
            return jwt.encode(
                payload,
                self.config['jwt_secret'],
                algorithm='HS256'
            )

        except Exception as e:
            logging.error(f"Error generating mobile token: {str(e)}")
            raise

    def _store_device(self, device_data: Dict) -> int:
        """Store device registration in database."""
        try:
            with self.db_manager.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO mobile_devices 
                    (user_id, device_token, platform, registered_at)
                    VALUES (?, ?, ?, ?)
                """, (
                    device_data['user_id'],
                    device_data['device_token'],
                    device_data['platform'],
                    device_data['registered_at']
                ))
                return cursor.lastrowid

        except Exception as e:
            logging.error(f"Error storing device: {str(e)}")
            raise

    def _send_fcm_notification(self, notification_data: Dict) -> Dict:
        """Send notification using Firebase Cloud Messaging."""
        try:
            headers = {
                'Authorization': f'key={self.api_key}',
                'Content-Type': 'application/json'
            }
            
            response = requests.post(
                self.fcm_url,
                headers=headers,
                data=json.dumps(notification_data)
            )
            
            response.raise_for_status()
            return response.json()

        except Exception as e:
            logging.error(f"Error sending FCM notification: {str(e)}")
            raise

    def _get_device_tokens(self, user_ids: List[int]) -> List[str]:
        """Get device tokens for specified users."""
        try:
            with self.db_manager.get_connection() as conn:
                cursor = conn.cursor()
                placeholders = ','.join('?' * len(user_ids))
                cursor.execute(f"""
                    SELECT device_token 
                    FROM mobile_devices 
                    WHERE user_id IN ({placeholders})
                """, user_ids)
                return [row[0] for row in cursor.fetchall()]

        except Exception as e:
            logging.error(f"Error getting device tokens: {str(e)}")
            raise
    
from typing import Dict, List, Optional, Union
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from fpdf import FPDF
import json
import logging
from datetime import datetime, timedelta
from enum import Enum
import io
import base64

class ReportType(Enum):
    STUDENT_PROGRESS = "student_progress"
    ENROLLMENT = "enrollment"
    FINANCIAL = "financial"
    VERIFICATION = "verification"
    ATTENDANCE = "attendance"
    CUSTOM = "custom"

class ReportFormat(Enum):
    PDF = "pdf"
    EXCEL = "excel"
    CSV = "csv"
    JSON = "json"

class ReportingSystem:
    def __init__(self, db_manager):
        """Initialize reporting system."""
        self.db_manager = db_manager
        
        # Configure logging
        logging.basicConfig(
            filename='reporting.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        
        # Set up plotting style
        plt.style.use('ggplot')
        sns.set_palette("husl")

    def generate_report(self,
                       report_type: ReportType,
                       start_date: datetime,
                       end_date: datetime,
                       format: ReportFormat = ReportFormat.PDF,
                       filters: Optional[Dict] = None,
                       custom_query: Optional[str] = None) -> Union[bytes, str]:
        """Generate a report based on specified parameters."""
        try:
            # Get report data
            if report_type == ReportType.CUSTOM and custom_query:
                data = self._execute_custom_query(custom_query)
            else:
                data = self._get_report_data(report_type, start_date, end_date, filters)

            # Generate visualizations if needed
            visualizations = self._generate_visualizations(data, report_type)

            # Format report based on requested format
            if format == ReportFormat.PDF:
                return self._generate_pdf_report(data, visualizations, report_type)
            elif format == ReportFormat.EXCEL:
                return self._generate_excel_report(data)
            elif format == ReportFormat.CSV:
                return self._generate_csv_report(data)
            elif format == ReportFormat.JSON:
                return self._generate_json_report(data)
            else:
                raise ValueError(f"Unsupported report format: {format}")

        except Exception as e:
            logging.error(f"Error generating report: {str(e)}")
            raise

    def schedule_report(self,
                       report_config: Dict,
                       schedule: str,
                       recipients: List[str]) -> Dict:
        """Schedule automated report generation and distribution."""
        try:
            schedule_data = {
                'report_config': report_config,
                'schedule': schedule,
                'recipients': recipients,
                'created_at': datetime.now().isoformat()
            }

            schedule_id = self._store_schedule(schedule_data)
            return {'schedule_id': schedule_id, **schedule_data}

        except Exception as e:
            logging.error(f"Error scheduling report: {str(e)}")
            raise

    def create_dashboard(self, metrics: List[str]) -> Dict:
        """Create a real-time dashboard with specified metrics."""
        try:
            dashboard_data = {}
            
            for metric in metrics:
                dashboard_data[metric] = self._calculate_metric(metric)
            
            return dashboard_data

        except Exception as e:
            logging.error(f"Error creating dashboard: {str(e)}")
            raise

    def _get_report_data(self,
                        report_type: ReportType,
                        start_date: datetime,
                        end_date: datetime,
                        filters: Optional[Dict] = None) -> pd.DataFrame:
        """Fetch data for specified report type."""
        try:
            query = self._get_report_query(report_type, start_date, end_date, filters)
            
            with self.db_manager.get_connection() as conn:
                return pd.read_sql_query(query, conn)

        except Exception as e:
            logging.error(f"Error fetching report data: {str(e)}")
            raise

    def _generate_visualizations(self,
                               data: pd.DataFrame,
                               report_type: ReportType) -> List[str]:
        """Generate visualizations based on report type and data."""
        try:
            visualizations = []
            
            if report_type == ReportType.ENROLLMENT:
                # Enrollment trends
                plt.figure(figsize=(10, 6))
                sns.lineplot(data=data, x='date', y='enrollment_count')
                plt.title('Enrollment Trends')
                plt.xticks(rotation=45)
                visualizations.append(self._save_plot_to_base64())

                # Programme distribution
                plt.figure(figsize=(10, 6))
                sns.barplot(data=data, x='programme', y='count')
                plt.title('Enrollment by Programme')
                plt.xticks(rotation=45)
                visualizations.append(self._save_plot_to_base64())

            elif report_type == ReportType.FINANCIAL:
                # Payment trends
                plt.figure(figsize=(10, 6))
                sns.lineplot(data=data, x='date', y='amount')
                plt.title('Payment Trends')
                plt.xticks(rotation=45)
                visualizations.append(self._save_plot_to_base64())

                # Payment method distribution
                plt.figure(figsize=(8, 8))
                data['payment_method'].value_counts().plot(kind='pie')
                plt.title('Payment Methods Distribution')
                visualizations.append(self._save_plot_to_base64())

            # Add more visualization types as needed

            return visualizations

        except Exception as e:
            logging.error(f"Error generating visualizations: {str(e)}")
            raise

    def _generate_pdf_report(self,
                           data: pd.DataFrame,
                           visualizations: List[str],
                           report_type: ReportType) -> bytes:
        """Generate PDF report with data and visualizations."""
        try:
            pdf = FPDF()
            pdf.add_page()

            # Add header
            pdf.set_font('Arial', 'B', 16)
            pdf.cell(0, 10, f'{report_type.value.title()} Report', 0, 1, 'C')
            pdf.ln(10)

            # Add summary statistics
            pdf.set_font('Arial', 'B', 12)
            pdf.cell(0, 10, 'Summary Statistics', 0, 1, 'L')
            pdf.set_font('Arial', '', 10)
            
            summary_stats = self._calculate_summary_statistics(data, report_type)
            for key, value in summary_stats.items():
                pdf.cell(0, 8, f'{key}: {value}', 0, 1, 'L')
            pdf.ln(10)

            # Add visualizations
            if visualizations:
                pdf.set_font('Arial', 'B', 12)
                pdf.cell(0, 10, 'Visualizations', 0, 1, 'L')
                
                for viz in visualizations:
                    pdf.image(viz, x=10, y=None, w=190)
                    pdf.ln(100)  # Space for the image

            # Add detailed data table
            pdf.add_page()
            pdf.set_font('Arial', 'B', 12)
            pdf.cell(0, 10, 'Detailed Data', 0, 1, 'L')
            
            # Convert DataFrame to table
            self._add_dataframe_to_pdf(pdf, data)

            return pdf.output(dest='S').encode('latin1')

        except Exception as e:
            logging.error(f"Error generating PDF report: {str(e)}")
            raise

    def _generate_excel_report(self, data: pd.DataFrame) -> bytes:
        """Generate Excel report."""
        try:
            output = io.BytesIO()
            with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
                data.to_excel(writer, sheet_name='Report', index=False)
                
                # Add summary sheet
                summary = pd.DataFrame([self._calculate_summary_statistics(data)])
                summary.to_excel(writer, sheet_name='Summary', index=False)
                
                # Auto-adjust columns width
                for sheet in writer.sheets.values():
                    for idx, col in enumerate(data.columns):
                        sheet.set_column(idx, idx, len(str(col)) + 2)

            return output.getvalue()

        except Exception as e:
            logging.error(f"Error generating Excel report: {str(e)}")
            raise

    def _save_plot_to_base64(self) -> str:
        """Convert matplotlib plot to base64 string."""
        try:
            buffer = io.BytesIO()
            plt.savefig(buffer, format='png', bbox_inches='tight')
            buffer.seek(0)
            image_png = buffer.getvalue()
            buffer.close()
            plt.close()
            
            return base64.b64encode(image_png).decode()

        except Exception as e:
            logging.error(f"Error saving plot: {str(e)}")
            raise

    def _calculate_metric(self, metric: str) -> Dict:
        """Calculate real-time metric value."""
        try:
            if metric == 'total_students':
                return self._get_total_students()
            elif metric == 'verification_rate':
                return self._get_verification_rate()
            elif metric == 'payment_status':
                return self._get_payment_status()
            # Add more metrics as needed
            else:
                raise ValueError(f"Unsupported metric: {metric}")

        except Exception as e:
            logging.error(f"Error calculating metric: {str(e)}")
            raise

    def _get_report_query(self,
                         report_type: ReportType,
                         start_date: datetime,
                         end_date: datetime,
                         filters: Optional[Dict] = None) -> str:
        """Generate SQL query based on report type and filters."""
        base_queries = {
            ReportType.ENROLLMENT: """
                SELECT 
                    DATE(created_at) as date,
                    COUNT(*) as enrollment_count,
                    programme_id,
                    (SELECT name FROM programmes WHERE id = students.programme_id) as programme
                FROM students
                WHERE created_at BETWEEN ? AND ?
                GROUP BY DATE(created_at), programme_id
            """,
            ReportType.FINANCIAL: """
                SELECT 
                    DATE(created_at) as date,
                    SUM(amount) as amount,
                    payment_method,
                    status
                FROM payments
                WHERE created_at BETWEEN ? AND ?
                GROUP BY DATE(created_at), payment_method
            """,
            # Add more report types as needed
        }

        query = base_queries.get(report_type)
        if not query:
            raise ValueError(f"Unsupported report type: {report_type}")

        # Add filters if provided
        if filters:
            where_clauses = []
            for key, value in filters.items():
                where_clauses.append(f"{key} = '{value}'")
            if where_clauses:
                query += " AND " + " AND ".join(where_clauses)

        return query

    def _calculate_summary_statistics(self,
                                   data: pd.DataFrame,
                                   report_type: ReportType) -> Dict:
        """Calculate summary statistics based on report type."""
        try:
            summary = {}
            
            if report_type == ReportType.ENROLLMENT:
                summary['Total Enrollments'] = data['enrollment_count'].sum()
                summary['Average Daily Enrollments'] = data['enrollment_count'].mean()
                summary['Peak Enrollment Day'] = data.loc[data['enrollment_count'].idxmax(), 'date']
                summary['Most Popular Programme'] = data.groupby('programme')['enrollment_count'].sum().idxmax()

            elif report_type == ReportType.FINANCIAL:
                summary['Total Revenue'] = data['amount'].sum()
                summary['Average Transaction Value'] = data['amount'].mean()
                summary['Most Common Payment Method'] = data['payment_method'].mode()[0]
                summary['Success Rate'] = (data['status'] == 'completed').mean() * 100

            # Add more report types as needed

            return summary

        except Exception as e:
            logging.error(f"Error calculating summary statistics: {str(e)}")
            raise

    def _add_dataframe_to_pdf(self, pdf: FPDF, df: pd.DataFrame):
        """Add DataFrame as table to PDF."""
        try:
            # Add headers
            pdf.set_font('Arial', 'B', 10)
            for col in df.columns:
                pdf.cell(40, 10, str(col), 1)
            pdf.ln()

            # Add rows
            pdf.set_font('Arial', '', 10)
            for _, row in df.iterrows():
                for item in row:
                    pdf.cell(40, 10, str(item), 1)
                pdf.ln()

        except Exception as e:
            logging.error(f"Error adding DataFrame to PDF: {str(e)}")
            raise
        
class ReportType(Enum):
    ENROLLMENT = "enrollment"
    FINANCIAL = "financial"
    VERIFICATION = "verification"
    ATTENDANCE = "attendance"
    PERFORMANCE = "performance"
    CUSTOM = "custom"

class ReportFormat(Enum):
    PDF = "pdf"
    EXCEL = "excel"
    CSV = "csv"
    JSON = "json"

class EnhancedReportingSystem:
    def __init__(self, db_manager):
        """Initialize reporting system with database connection."""
        self.db_manager = db_manager
        self.setup_logging()
        self.setup_styling()
        self.initialize_queries()

    def setup_logging(self):
        """Configure logging for the reporting system."""
        logging.basicConfig(
            filename='reporting.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )

    def setup_styling(self):
        """Set up plotting style for visualizations."""
        plt.style.use('seaborn')
        sns.set_palette("husl")
        plt.rcParams['figure.figsize'] = [10, 6]
        plt.rcParams['figure.dpi'] = 100

    def initialize_queries(self):
        """Initialize SQL queries for different report types."""
        self.queries = {
            ReportType.ENROLLMENT: """
                SELECT 
                    DATE(s.created_at) as date,
                    COUNT(*) as enrollment_count,
                    p.name as programme_name
                FROM students s
                LEFT JOIN programmes p ON s.programme_id = p.id
                WHERE s.created_at BETWEEN :start_date AND :end_date
                GROUP BY DATE(s.created_at), p.name
                ORDER BY date
            """,
            ReportType.FINANCIAL: """
                SELECT 
                    DATE(created_at) as date,
                    SUM(amount) as total_amount,
                    payment_method,
                    status
                FROM payments
                WHERE created_at BETWEEN :start_date AND :end_date
                GROUP BY DATE(created_at), payment_method, status
                ORDER BY date
            """,
            ReportType.VERIFICATION: """
                SELECT 
                    DATE(uploaded_at) as date,
                    document_type,
                    status,
                    COUNT(*) as document_count
                FROM documents
                WHERE uploaded_at BETWEEN :start_date AND :end_date
                GROUP BY DATE(uploaded_at), document_type, status
                ORDER BY date
            """
        }

    def generate_report(self,
                       report_type: ReportType,
                       start_date: datetime,
                       end_date: datetime,
                       format: ReportFormat = ReportFormat.PDF,
                       filters: Optional[Dict] = None) -> Union[bytes, str]:
        """Generate a report with the specified parameters."""
        try:
            # Validate dates
            if start_date > end_date:
                raise ValueError("Start date must be before end date")

            # Convert dates to ISO format strings for SQL
            params = {
                'start_date': start_date.isoformat(),
                'end_date': end_date.isoformat()
            }

            # Add any additional filters to params
            if filters:
                params.update(filters)

            # Get report data
            data = self._get_report_data(report_type, params)

            # Generate visualizations
            visualizations = self._generate_visualizations(data, report_type)

            # Calculate summary statistics
            summary = self._calculate_summary_statistics(data, report_type)

            # Format report based on requested format
            if format == ReportFormat.PDF:
                return self._generate_pdf_report(data, visualizations, summary, report_type)
            elif format == ReportFormat.EXCEL:
                return self._generate_excel_report(data, summary)
            elif format == ReportFormat.CSV:
                return self._generate_csv_report(data)
            elif format == ReportFormat.JSON:
                return self._generate_json_report(data, summary)
            else:
                raise ValueError(f"Unsupported report format: {format}")

        except Exception as e:
            logging.error(f"Error generating report: {str(e)}")
            raise

    def _get_report_data(self, report_type: ReportType, params: Dict) -> pd.DataFrame:
        """Fetch and process data for the report."""
        try:
            query = self.queries.get(report_type)
            if not query:
                raise ValueError(f"No query defined for report type: {report_type}")

            with self.db_manager.get_connection() as conn:
                return pd.read_sql_query(query, conn, params=params)

        except Exception as e:
            logging.error(f"Error fetching report data: {str(e)}")
            raise

    def _generate_visualizations(self, data: pd.DataFrame, report_type: ReportType) -> List[str]:
        """Generate visualizations based on report type and data."""
        try:
            visualizations = []

            if report_type == ReportType.ENROLLMENT:
                # Enrollment trends over time
                plt.figure()
                sns.lineplot(data=data, x='date', y='enrollment_count', hue='programme_name')
                plt.title('Enrollment Trends by Programme')
                plt.xticks(rotation=45)
                visualizations.append(self._save_plot_to_base64())

                # Programme distribution pie chart
                plt.figure()
                programme_totals = data.groupby('programme_name')['enrollment_count'].sum()
                plt.pie(programme_totals, labels=programme_totals.index, autopct='%1.1f%%')
                plt.title('Enrollment Distribution by Programme')
                visualizations.append(self._save_plot_to_base64())

            elif report_type == ReportType.FINANCIAL:
                # Payment trends over time
                plt.figure()
                sns.lineplot(data=data, x='date', y='total_amount')
                plt.title('Payment Trends')
                plt.xticks(rotation=45)
                visualizations.append(self._save_plot_to_base64())

                # Payment method distribution
                plt.figure()
                payment_methods = data.groupby('payment_method')['total_amount'].sum()
                plt.pie(payment_methods, labels=payment_methods.index, autopct='%1.1f%%')
                plt.title('Payment Distribution by Method')
                visualizations.append(self._save_plot_to_base64())

            return visualizations

        except Exception as e:
            logging.error(f"Error generating visualizations: {str(e)}")
            raise

    def _save_plot_to_base64(self) -> str:
        """Convert matplotlib plot to base64 string."""
        try:
            buffer = io.BytesIO()
            plt.savefig(buffer, format='png', bbox_inches='tight')
            buffer.seek(0)
            image_png = buffer.getvalue()
            buffer.close()
            plt.close()

            return base64.b64encode(image_png).decode()

        except Exception as e:
            logging.error(f"Error saving plot: {str(e)}")
            raise

    def _calculate_summary_statistics(self, data: pd.DataFrame, report_type: ReportType) -> Dict[str, Any]:
        """Calculate summary statistics based on report type."""
        try:
            summary = {}

            if report_type == ReportType.ENROLLMENT:
                summary['Total Enrollments'] = data['enrollment_count'].sum()
                summary['Average Daily Enrollments'] = round(data['enrollment_count'].mean(), 2)
                summary['Peak Enrollment Day'] = data.loc[data['enrollment_count'].idxmax(), 'date']
                summary['Most Popular Programme'] = data.groupby('programme_name')['enrollment_count'].sum().idxmax()

            elif report_type == ReportType.FINANCIAL:
                summary['Total Revenue'] = f"${data['total_amount'].sum():,.2f}"
                summary['Average Transaction Value'] = f"${data['total_amount'].mean():,.2f}"
                summary['Most Used Payment Method'] = data.groupby('payment_method')['total_amount'].sum().idxmax()
                summary['Success Rate'] = f"{(data['status'] == 'completed').mean() * 100:.1f}%"

            return summary

        except Exception as e:
            logging.error(f"Error calculating summary statistics: {str(e)}")
            raise



        
        
class DataExporter:
    """Utility class for data export operations."""
    
    @staticmethod
    def export_to_csv(data: pd.DataFrame, filename: str) -> str:
        """Export data to CSV file."""
        try:
            filepath = f"exports/{filename}.csv"
            data.to_csv(filepath, index=False)
            return filepath
        except Exception as e:
            logging.error(f"Error exporting to CSV: {str(e)}")
            raise

class DataValidator:
    """Utility class for data validation."""
    
    @staticmethod
    def validate_email(email: str) -> bool:
        """Validate email format."""
        import re
        pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
        return bool(re.match(pattern, email))

    @staticmethod
    def validate_phone(phone: str) -> bool:
        """Validate phone number format."""
        import re
        pattern = r'^\+?1?\d{9,15}$'
        return bool(re.match(pattern, phone))

class SystemMonitor:
    """Utility class for system monitoring."""
    
    @staticmethod
    def check_system_health() -> Dict:
        """Check system health metrics."""
        import psutil
        return {
            'cpu_usage': psutil.cpu_percent(),
            'memory_usage': psutil.virtual_memory().percent,
            'disk_usage': psutil.disk_usage('/').percent
        }

class BackupManager:
    """Utility class for database backup operations."""
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        
    def create_backup(self) -> str:
        """Create database backup."""
        import shutil
        from datetime import datetime
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_path = f"backups/backup_{timestamp}.db"
        
        shutil.copy2(self.db_path, backup_path)
        return backup_path

class CacheManager:
    """Utility class for caching frequently accessed data."""
    
    def __init__(self):
        self.cache = {}
        self.cache_timeout = 300  # 5 minutes
        
    def get(self, key: str) -> Any:
        """Get value from cache."""
        if key in self.cache:
            value, timestamp = self.cache[key]
            if datetime.now().timestamp() - timestamp < self.cache_timeout:
                return value
            else:
                del self.cache[key]
        return None
        
    def set(self, key: str, value: Any):
        """Set value in cache."""
        self.cache[key] = (value, datetime.now().timestamp())
    
    
    
    
    
    
    
    

class EmailManager:
    def __init__(self, smtp_server: str, smtp_port: int, sender_email: str, sender_password: str):
        """Initialize email manager with SMTP credentials."""
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.sender_email = sender_email
        self.sender_password = sender_password
    
    def send_email(self, recipient: str, subject: str, body: str) -> bool:
        """Send an email to a single recipient."""
        try:
            msg = MIMEMultipart()
            msg['From'] = self.sender_email
            msg['To'] = recipient
            msg['Subject'] = subject
            msg.attach(MIMEText(body, 'plain'))
            
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.sender_email, self.sender_password)
                server.send_message(msg)
            return True
        except Exception as e:
            logging.error(f"Failed to send email: {str(e)}")
            return False
    
    def send_bulk_emails(self, recipients: List[str], subject: str, body: str) -> Dict[str, bool]:
        """Send emails to multiple recipients and return success status for each."""
        results = {}
        for recipient in recipients:
            results[recipient] = self.send_email(recipient, subject, body)
        return results

class SecurityManager:
    @staticmethod
    def hash_password(password: str) -> str:
        """Hash a password using SHA-256."""
        return hashlib.sha256(password.encode()).hexdigest()
    
    @staticmethod
    def verify_password(password: str, hash_value: str) -> bool:
        """Verify a password against its hash."""
        return SecurityManager.hash_password(password) == hash_value
    
    @staticmethod
    def generate_session_id() -> str:
        """Generate a unique session ID."""
        return hashlib.sha256(os.urandom(24)).hexdigest()

# Initialize logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename='system.log'
)

class StudentRegistration:
    def __init__(self, db_manager, email_manager):
        """Initialize registration component with database and email managers."""
        self.db_manager = db_manager
        self.email_manager = email_manager

    def show_registration_form(self):
        st.title("Student Registration")
        
        # Create two columns - one for the form and one for the login button
        col1, col2 = st.columns([3, 1])
        
        with col1:
            with st.form("registration_form"):
                name = st.text_input("Full Name")
                email = st.text_input("Email")
                phone = st.text_input("Phone Number")
                programme = st.selectbox("Programme", self.get_programmes())
                level = st.selectbox("Level", ["100", "200", "300", "400"])
                
                submit_button = st.form_submit_button("Register")
                
                if submit_button:
                    self.handle_registration(name, email, phone, programme, level)
        



    def process_registration(self, name, email, phone, programme, level):
        """Process student registration with validation."""
        try:
            # Validate required fields
            if not all([name, email, phone, programme, level]):
                return {
                    "success": False,
                    "message": "Please fill in all required fields."
                }
            
            # Validate email format
            if not self.validate_email(email):
                return {
                    "success": False,
                    "message": "Please enter a valid email address."
                }
            
            # Validate phone format
            if not self.validate_phone(phone):
                return {
                    "success": False,
                    "message": "Please enter a valid phone number."
                }
            
            with self.db_manager.get_connection() as conn:
                cursor = conn.cursor()
                
                # Check if email already exists
                cursor.execute("SELECT id FROM students WHERE email = ?", (email,))
                if cursor.fetchone():
                    return {
                        "success": False,
                        "message": "This email address is already registered."
                    }
                
                # Get programme_id
                cursor.execute("SELECT id FROM programmes WHERE name = ?", (programme,))
                programme_id = cursor.fetchone()[0]
                
                # Insert new student
                cursor.execute("""
                    INSERT INTO students (name, email, phone, programme_id, level, status)
                    VALUES (?, ?, ?, ?, ?, 'active')
                """, (name, email, phone, programme_id, level))
                
                # Send welcome email
                self.send_welcome_email(name, email, programme, level)
                
                return {
                    "success": True,
                    "message": "Registration successful! You can now log in with your email address."
                }
                
        except Exception as e:
            logging.error(f"Registration error: {str(e)}")
            return {
                "success": False,
                "message": "An error occurred during registration. Please try again."
            }

    def get_programmes(self):
        """
        Get list of all available programmes from the database.
        
        Returns:
            List[str]: List of programme names
        """
        try:
            with self.db_manager.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT name FROM programmes ORDER BY name")
                return [row[0] for row in cursor.fetchall()]
        except Exception as e:
            logging.error(f"Error fetching programmes: {str(e)}")
            # Return a default list if database query fails
            return ["No programmes available"]

    def handle_registration(self, name: str, email: str, phone: str, programme: str, level: str):
        """
        Handle the student registration process.
        
        Args:
            name (str): Student's full name
            email (str): Student's email address
            phone (str): Student's phone number
            programme (str): Selected programme name
            level (str): Selected study level
        """
        if not all([name, email, phone, programme, level]):
            st.error("Please fill in all required fields.")
            return

        try:
            # Validate email format
            if not self.validate_email(email):
                st.error("Please enter a valid email address.")
                return

            # Validate phone format
            if not self.validate_phone(phone):
                st.error("Please enter a valid phone number.")
                return

            with self.db_manager.get_connection() as conn:
                cursor = conn.cursor()
                
                # Check if email already exists
                cursor.execute("SELECT id FROM students WHERE email = ?", (email,))
                if cursor.fetchone():
                    st.error("This email address is already registered.")
                    return
                
                # Get programme_id
                cursor.execute("SELECT id FROM programmes WHERE name = ?", (programme,))
                programme_result = cursor.fetchone()
                if not programme_result:
                    st.error("Selected programme is not valid.")
                    return
                    
                programme_id = programme_result[0]
                
                # Insert new student
                cursor.execute("""
                    INSERT INTO students (name, email, phone, programme_id, level, status)
                    VALUES (?, ?, ?, ?, ?, 'active')
                """, (name, email, phone, programme_id, level))
                
                conn.commit()
                
                # Send welcome email
                self.send_welcome_email(name, email, programme, level)
                
                st.success("Registration successful! You can now log in with your email address.")
                
        except Exception as e:
            logging.error(f"Registration error: {str(e)}")
            st.error("An error occurred during registration. Please try again.")
        
    def validate_email(self, email):
        """Validate email format."""
        import re
        pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
        return bool(re.match(pattern, email))

    def validate_phone(self, phone):
        """Validate phone number format."""
        import re
        pattern = r'^\+?1?\d{9,15}$'
        return bool(re.match(pattern, phone))

    def send_welcome_email(self, name, email, programme, level):
        """Send welcome email to newly registered student."""
        subject = "Welcome to Professional Programmes"
        message = f"""
            Dear {name},
            
            Welcome to our Professional Programmes! Your registration was successful.
            
            Programme: {programme}
            Level: {level}
            
            You can now log in to your student portal using your email address.
            
            Best regards,
            Administration Team
        """
        
        self.email_manager.send_email(email, subject, message)

class AdminPortal:
    def __init__(self, db_manager: DatabaseManager, email_manager: EmailManager):
        """Initialize AdminPortal with database and email managers."""
        self.db_manager = db_manager
        self.email_manager = email_manager
        self.current_admin = None

    def login(self, email: str, password: str) -> bool:
        """Authenticate administrator login."""
        with self.db_manager.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, name, email, password_hash, role FROM administrators WHERE email = ?",
                (email,)
            )
            admin = cursor.fetchone()
            
            if admin and SecurityManager.verify_password(password, admin[3]):
                self.current_admin = {
                    'id': admin[0],
                    'name': admin[1],
                    'email': admin[2],
                    'role': admin[4]
                }
                self.log_audit("login", "Administrator logged in")
                return True
            return False

    def log_audit(self, action: str, description: str):
        """Log administrator actions."""
        if not self.current_admin:
            return
            
        with self.db_manager.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO audit_logs (admin_id, action, description) VALUES (?, ?, ?)",
                (self.current_admin['id'], action, description)
            )

    def add_student(self, student_data: Dict[str, Any]) -> bool:
        """Add a new student to the system."""
        try:
            with self.db_manager.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO students (name, email, phone, programme_id, level)
                    VALUES (?, ?, ?, ?, ?)
                """, (
                    student_data['name'],
                    student_data['email'],
                    student_data['phone'],
                    student_data['programme_id'],
                    student_data['level']
                ))
                self.log_audit("add_student", f"Added student: {student_data['email']}")
                return True
        except sqlite3.IntegrityError:
            return False

    def verify_document(self, document_id: int, status: str, feedback: str = None) -> bool:
        """Verify or reject a student document."""
        try:
            with self.db_manager.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE documents 
                    SET status = ?, admin_feedback = ? 
                    WHERE id = ?
                """, (status, feedback, document_id))
                
                # Get student email for notification
                cursor.execute("""
                    SELECT s.email, d.document_type 
                    FROM documents d 
                    JOIN students s ON d.student_id = s.id 
                    WHERE d.id = ?
                """, (document_id,))
                
                student_email, doc_type = cursor.fetchone()
                
                # Send email notification
                subject = f"Document Verification Status Update"
                body = f"Your {doc_type} has been {status}. "
                if feedback:
                    body += f"Feedback: {feedback}"
                
                self.email_manager.send_email(student_email, subject, body)
                self.log_audit("verify_document", f"Document {document_id} {status}")
                return True
        except Exception as e:
            logging.error(f"Document verification failed: {str(e)}")
            return False

    def get_analytics(self) -> Dict[str, Any]:
        """Generate analytics data for dashboard."""
        with self.db_manager.get_connection() as conn:
            cursor = conn.cursor()
            analytics = {}
            
            # Total students
            cursor.execute("SELECT COUNT(*) FROM students")
            analytics['total_students'] = cursor.fetchone()[0]
            
            # Students per programme
            cursor.execute("""
                SELECT p.name, COUNT(s.id) 
                FROM programmes p 
                LEFT JOIN students s ON p.id = s.programme_id 
                GROUP BY p.id
            """)
            analytics['students_per_programme'] = dict(cursor.fetchall())
            
            # Document verification status
            cursor.execute("""
                SELECT status, COUNT(*) 
                FROM documents 
                GROUP BY status
            """)
            analytics['document_status'] = dict(cursor.fetchall())
            
            return analytics

    def bulk_email(self, filters: Dict[str, Any], subject: str, body: str) -> Dict[str, int]:
        """Send bulk emails to filtered students."""
        with self.db_manager.get_connection() as conn:
            cursor = conn.cursor()
            
            # Build query based on filters
            query = "SELECT email FROM students WHERE 1=1"
            params = []
            
            if filters.get('programme_id'):
                query += " AND programme_id = ?"
                params.append(filters['programme_id'])
            
            if filters.get('level'):
                query += " AND level = ?"
                params.append(filters['level'])
            
            cursor.execute(query, params)
            recipients = [row[0] for row in cursor.fetchall()]
            
            # Send emails
            results = self.email_manager.send_bulk_emails(recipients, subject, body)
            
            # Log the bulk email action
            self.log_audit(
                "bulk_email",
                f"Sent bulk email to {len(recipients)} recipients"
            )
            
            return {
                'total': len(recipients),
                'success': sum(1 for v in results.values() if v),
                'failed': sum(1 for v in results.values() if not v)
            }

class StudentPortal:
    def __init__(self, db_manager: DatabaseManager, email_manager: EmailManager):
        """Initialize StudentPortal with database and email managers."""
        self.db_manager = db_manager
        self.email_manager = email_manager
        self.current_student = None

    def register(self, student_data: Dict[str, Any]) -> bool:
        """Register a new student."""
        try:
            with self.db_manager.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO students (name, email, phone, programme_id, level)
                    VALUES (?, ?, ?, ?, ?)
                """, (
                    student_data['name'],
                    student_data['email'],
                    student_data['phone'],
                    student_data['programme_id'],
                    student_data['level']
                ))
                
                # Send welcome email
                subject = "Welcome to Professional Programmes Management System"
                body = f"Dear {student_data['name']},\n\nWelcome to our system. Your registration was successful."
                self.email_manager.send_email(student_data['email'], subject, body)
                
                return True
        except sqlite3.IntegrityError:
            return False

    def login(self, email: str) -> bool:
        """Student login (simplified for demo - would need proper authentication)."""
        with self.db_manager.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, name, email, programme_id, level FROM students WHERE email = ?",
                (email,)
            )
            student = cursor.fetchone()
            
            if student:
                self.current_student = {
                    'id': student[0],
                    'name': student[1],
                    'email': student[2],
                    'programme_id': student[3],
                    'level': student[4]
                }
                return True
            return False

    def upload_document(self, document_type: str, file_path: str) -> bool:
        """Upload a new document."""
        if not self.current_student:
            return False
            
        try:
            with self.db_manager.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO documents (student_id, document_type, file_path)
                    VALUES (?, ?, ?)
                """, (self.current_student['id'], document_type, file_path))
                return True
        except Exception as e:
            logging.error(f"Document upload failed: {str(e)}")
            return False

    def get_document_status(self) -> List[Dict[str, Any]]:
        """Get status of all uploaded documents."""
        if not self.current_student:
            return []
            
        with self.db_manager.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT document_type, status, admin_feedback, uploaded_at
                FROM documents
                WHERE student_id = ?
                ORDER BY uploaded_at DESC
            """, (self.current_student['id'],))
            
            columns = ['document_type', 'status', 'admin_feedback', 'uploaded_at']
            return [dict(zip(columns, row)) for row in cursor.fetchall()]

    def get_upcoming_events(self) -> List[Dict[str, Any]]:
        """Get upcoming events for student's programme."""
        if not self.current_student:
            return []
            
        with self.db_manager.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT title, description, date
                FROM events
                WHERE programme_id = ? AND date >= DATE('now')
                ORDER BY date
                LIMIT 10
            """, (self.current_student['programme_id'],))
            
            columns = ['title', 'description', 'date']
            return [dict(zip(columns, row)) for row in cursor.fetchall()]
        
from dataclasses import dataclass
import yaml

@dataclass
class EmailConfig:
    smtp_server: str = "smtp.gmail.com"
    smtp_port: int = 587
    sender_email: str = ""
    sender_password: str = ""
    
@dataclass
class SecurityConfig:
    jwt_secret: str = "default-jwt-secret"
    session_timeout: int = 30
    max_login_attempts: int = 3
    
@dataclass
class DatabaseConfig:
    db_path: str = "students_management.db"
    backup_path: str = "backups"
    max_connections: int = 10

class ConfigurationManager:
    """Manages application configuration and secrets."""
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize configuration manager."""
        self.config_path = config_path or "config"
        self.secrets_path = os.path.join(self.config_path, "secrets.yaml")
        self.config_file = os.path.join(self.config_path, "config.yaml")
        
        # Initialize configurations with defaults
        self.email_config = EmailConfig()
        self.security_config = SecurityConfig()
        self.database_config = DatabaseConfig()
        
        # Load configurations
        self._load_config()
        self._load_secrets()
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )

    def _load_config(self):
        """Load configuration from file or environment variables."""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    config = yaml.safe_load(f)
                    
                    # Update email config
                    if 'email' in config:
                        self.email_config = EmailConfig(**config['email'])
                        
                    # Update security config
                    if 'security' in config:
                        self.security_config = SecurityConfig(**config['security'])
                        
                    # Update database config
                    if 'database' in config:
                        self.database_config = DatabaseConfig(**config['database'])
            else:
                self._load_from_env()
                
        except Exception as e:
            logging.error(f"Error loading config: {str(e)}")
            self._load_from_env()

    def _load_secrets(self):
        """Load secrets from file or environment variables."""
        try:
            if os.path.exists(self.secrets_path):
                with open(self.secrets_path, 'r') as f:
                    secrets = yaml.safe_load(f)
                    
                    # Update email secrets
                    if 'email' in secrets:
                        self.email_config.sender_email = secrets['email'].get('sender_email', '')
                        self.email_config.sender_password = secrets['email'].get('sender_password', '')
                        
                    # Update security secrets
                    if 'security' in secrets:
                        self.security_config.jwt_secret = secrets['security'].get('jwt_secret', '')
            else:
                self._load_secrets_from_env()
                
        except Exception as e:
            logging.error(f"Error loading secrets: {str(e)}")
            self._load_secrets_from_env()

    def _load_from_env(self):
        """Load configuration from environment variables."""
        # Email configuration
        self.email_config.smtp_server = os.getenv('SMTP_SERVER', self.email_config.smtp_server)
        self.email_config.smtp_port = int(os.getenv('SMTP_PORT', self.email_config.smtp_port))
        
        # Security configuration
        self.security_config.session_timeout = int(os.getenv('SESSION_TIMEOUT', 
                                                           self.security_config.session_timeout))
        self.security_config.max_login_attempts = int(os.getenv('MAX_LOGIN_ATTEMPTS',
                                                              self.security_config.max_login_attempts))
        
        # Database configuration
        self.database_config.db_path = os.getenv('DB_PATH', self.database_config.db_path)
        self.database_config.backup_path = os.getenv('BACKUP_PATH', self.database_config.backup_path)

    def _load_secrets_from_env(self):
        """Load secrets from environment variables."""
        # Email secrets
        self.email_config.sender_email = os.getenv('SENDER_EMAIL', '')
        self.email_config.sender_password = os.getenv('SENDER_PASSWORD', '')
        
        # Security secrets
        self.security_config.jwt_secret = os.getenv('JWT_SECRET', '')

    def get_email_config(self) -> EmailConfig:
        """Get email configuration."""
        return self.email_config
    
    def get_security_config(self) -> SecurityConfig:
        """Get security configuration."""
        return self.security_config
    
    def get_database_config(self) -> DatabaseConfig:
        """Get database configuration."""
        return self.database_config
    
    def update_config(self, section: str, updates: Dict[str, Any]) -> bool:
        """Update configuration values."""
        try:
            if section == 'email':
                for key, value in updates.items():
                    setattr(self.email_config, key, value)
            elif section == 'security':
                for key, value in updates.items():
                    setattr(self.security_config, key, value)
            elif section == 'database':
                for key, value in updates.items():
                    setattr(self.database_config, key, value)
            else:
                return False
            
            self._save_config()
            return True
            
        except Exception as e:
            logging.error(f"Error updating config: {str(e)}")
            return False

    def _save_config(self):
        """Save current configuration to file."""
        try:
            config = {
                'email': {
                    'smtp_server': self.email_config.smtp_server,
                    'smtp_port': self.email_config.smtp_port
                },
                'security': {
                    'session_timeout': self.security_config.session_timeout,
                    'max_login_attempts': self.security_config.max_login_attempts
                },
                'database': {
                    'db_path': self.database_config.db_path,
                    'backup_path': self.database_config.backup_path,
                    'max_connections': self.database_config.max_connections
                }
            }
            
            os.makedirs(self.config_path, exist_ok=True)
            with open(self.config_file, 'w') as f:
                yaml.dump(config, f)
                
        except Exception as e:
            logging.error(f"Error saving config: {str(e)}")
          


class MainApp:
    def __init__(self):
        """Initialize the main application."""
        # First, setup logging
        self.setup_logging()
        
        # Initialize configuration manager first since other components depend on it
        self.config_manager = ConfigurationManager()
        
        # Get configurations
        db_config = self.config_manager.get_database_config()
        email_config = self.config_manager.get_email_config()
        security_config = self.config_manager.get_security_config()
        
        # Initialize database manager
        self.db_manager = DatabaseManager(db_config.db_path)
        
        # Initialize email manager
        self.email_manager = EmailManager(
            smtp_server=email_config.smtp_server,
            smtp_port=email_config.smtp_port,
            sender_email=email_config.sender_email,
            sender_password=email_config.sender_password
        )
        
        # Initialize security manager
        self.security_manager = SecurityManager()
        
        # Initialize session state
        self.initialize_session_state()
        
        # Initialize student registration
        self.student_registration = StudentRegistration(self.db_manager, self.email_manager)
        
        # Initialize other components
        self.scheduling_system = SchedulingSystem(self.db_manager)
        self.reporting_system = ReportingSystem(self.db_manager)
        self.system_monitor = SystemMonitor()
        self.backup_manager = BackupManager(db_config.db_path)
        self.cache_manager = CacheManager()
        
        # Initialize mobile integration
        firebase_config = getattr(self.config_manager, 'firebase', {})
        self.mobile_integration = MobileIntegration({
            'jwt_secret': security_config.jwt_secret,
            'fcm_api_key': firebase_config.get('fcm_api_key', '')
        })
    def setup_logging(self):
        """Configure logging for the application."""
        logging.basicConfig(
            filename='app.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        
    def authenticate_user(self, email: str, password: str) -> bool:
        """
        Authenticate user login attempt.
        Returns True if authentication successful, False otherwise.
        """
        try:
            # Input validation
            if not email or not password:
                return False
                
            # Check admin login first
            with self.db_manager.get_connection() as conn:
                cursor = conn.cursor()
                
                # Check admin credentials
                cursor.execute("""
                    SELECT id, name, password_hash, role 
                    FROM administrators 
                    WHERE email = ?
                """, (email,))
                admin = cursor.fetchone()
                
                if admin and self.security_manager.verify_password(password, admin[2]):
                    # Set admin session data
                    st.session_state.user_role = "admin"
                    st.session_state.user_id = admin[0]
                    st.session_state.user_name = admin[1]
                    logging.info(f"Admin login successful: {email}")
                    return True
                    
                # If not admin, check student credentials
                cursor.execute("""
                    SELECT id, name 
                    FROM students 
                    WHERE email = ?
                """, (email,))
                student = cursor.fetchone()
                
                if student:
                    # For demo purposes, students can login with just email
                    # In production, implement proper student password verification
                    st.session_state.user_role = "student"
                    st.session_state.user_id = student[0]
                    st.session_state.user_name = student[1]
                    logging.info(f"Student login successful: {email}")
                    return True
                    
                logging.warning(f"Failed login attempt for email: {email}")
                return False
                
        except Exception as e:
            logging.error(f"Authentication error: {str(e)}")
            return False

    def initialize_session_state(self):
        """Initialize Streamlit session state variables."""
        if 'logged_in' not in st.session_state:
            st.session_state.logged_in = False
        if 'user_role' not in st.session_state:
            st.session_state.user_role = None
        if 'user_id' not in st.session_state:
            st.session_state.user_id = None
        if 'user_name' not in st.session_state:
            st.session_state.user_name = None

    def setup_database(self):
        """Setup database connection and initialize managers."""
        self.db_manager = DatabaseManager("students_management.db")
        
    def initialize_managers(self):
        """Initialize various system managers."""
        # Initialize core managers
        self.security_manager = SecurityManager()
        
        # Get email configuration
        email_config = self.config_manager.get_email_config()
        self.email_manager = EmailManager(
            smtp_server=email_config.smtp_server,
            smtp_port=email_config.smtp_port,
            sender_email=email_config.sender_email,
            sender_password=email_config.sender_password
        )
        
        # Initialize feature managers
        self.scheduling_system = SchedulingSystem(self.db_manager)
        self.reporting_system = ReportingSystem(self.db_manager)
        self.system_monitor = SystemMonitor()
        self.backup_manager = BackupManager(self.config_manager.get_database_config().db_path)
        self.cache_manager = CacheManager()

    def run(self):
        """Run the main application."""
         # Inject custom CSS
        st.markdown("""
            <style>
        /* Base Theme Variables */
        :root {
            --primary-color: #2E3192;
            --secondary-color: #1E88E5;
            --success-color: #4CAF50;
            --warning-color: #FFC107;
            --danger-color: #F44336;
            --text-color: #333333;
            --bg-color: #FFFFFF;
            --sidebar-bg: #F8F9FA;
            --card-bg: #FFFFFF;
            --border-color: #E0E0E0;
            --shadow: 0 2px 4px rgba(0,0,0,0.1);
        }

        /* Global Container Styles */
        .stApp {
            background-color: #F5F7FA;
        }

        .main .block-container {
            max-width: 1200px;
            padding: 2rem 1rem;
            margin: 0 auto;
        }

        /* Form Controls */
        .stSelectbox, .stTextInput, .stTextArea {
            width: 100%;
            max-width: 500px;
        }

        .stSelectbox > div,
        .stTextInput > div,
        .stTextArea > div {
            width: 100%;
        }

        /* Input Fields */
        .stTextInput > div > div {
            border-radius: 4px;
            border: 1px solid var(--border-color);
            padding: 0.5rem;
            width: 100%;
            max-width: 100%;
            box-sizing: border-box;
        }

        /* Select Boxes */
        .stSelectbox > div > div {
            border-radius: 4px;
            border: 1px solid var(--border-color);
            max-width: 100%;
        }

        /* Cards and Containers */
        .dashboard-card {
            background: var(--card-bg);
            padding: 1.5rem;
            border-radius: 8px;
            box-shadow: var(--shadow);
            margin-bottom: 1rem;
            width: 100%;
            box-sizing: border-box;
        }

        /* Grid Layout */
        .grid-container {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1rem;
            width: 100%;
            margin-bottom: 1rem;
        }

        /* Responsive Tables */
        .stDataFrame {
            width: 100%;
            overflow-x: auto;
        }

        .stDataFrame table {
            min-width: 600px;
            width: 100%;
        }

        /* Form Layout */
        .form-container {
            max-width: 500px;
            margin: 0 auto;
            padding: 1rem;
        }

        .form-group {
            margin-bottom: 1rem;
            width: 100%;
        }

        /* Buttons */
        .stButton > button {
            width: auto;
            min-width: 120px;
            max-width: 100%;
            padding: 0.5rem 1rem;
            background-color: var(--primary-color);
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            transition: all 0.3s ease;
        }

        .stButton > button:hover {
            background-color: var(--secondary-color);
            transform: translateY(-1px);
        }

        /* Metrics */
        .stMetric {
            background: var(--card-bg);
            padding: 1rem;
            border-radius: 8px;
            box-shadow: var(--shadow);
            width: 100%;
        }

        /* Sidebar */
        .css-1d391kg {
            width: 250px;
            max-width: 100%;
            background-color: var(--sidebar-bg);
        }

        /* Expander */
        .streamlit-expander {
            border: 1px solid var(--border-color);
            border-radius: 8px;
            margin-bottom: 1rem;
            width: 100%;
        }

        /* File Uploader */
        .stUploader {
            width: 100%;
            max-width: 500px;
            border: 2px dashed var(--border-color);
            border-radius: 8px;
            padding: 1rem;
        }

        /* Media Queries */
        @media screen and (max-width: 768px) {
            .main .block-container {
                padding: 1rem 0.5rem;
            }
            
            .dashboard-card {
                padding: 1rem;
            }
            
            .grid-container {
                grid-template-columns: 1fr;
            }
            
            .stButton > button {
                width: 100%;
            }
        }

        /* Custom Column Layout */
        .custom-columns {
            display: flex;
            flex-wrap: wrap;
            gap: 1rem;
            width: 100%;
        }

        .custom-column {
            flex: 1;
            min-width: 250px;
        }

        /* Status Badges */
        .status-badge {
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 12px;
            font-size: 0.875rem;
            font-weight: 500;
        }

        .status-badge.active {
            background-color: #E8F5E9;
            color: #2E7D32;
        }

        .status-badge.pending {
            background-color: #FFF3E0;
            color: #E65100;
        }

        .status-badge.inactive {
            background-color: #FFEBEE;
            color: #C62828;
        }

        /* Charts and Visualizations */
        .chart-container {
            width: 100%;
            height: 400px;
            margin-bottom: 1rem;
        }

        /* Tooltips */
        .tooltip {
            position: relative;
            display: inline-block;
        }

        .tooltip .tooltip-text {
            visibility: hidden;
            background-color: #333;
            color: #fff;
            text-align: center;
            padding: 5px;
            border-radius: 4px;
            position: absolute;
            z-index: 1;
            bottom: 125%;
            left: 50%;
            transform: translateX(-50%);
            opacity: 0;
            transition: opacity 0.3s;
        }

        .tooltip:hover .tooltip-text {
            visibility: visible;
            opacity: 1;
        }
            </style>
        """, unsafe_allow_html=True)
        
        st.title("Professional Programmes Management System")
        
        # Check system health
        self.monitor_system_health()
        
        if not st.session_state.logged_in:
            self.show_login_page()
        else:
            self.show_main_interface()

    def monitor_system_health(self):
        """Monitor and display system health metrics."""
        health_metrics = self.system_monitor.check_system_health()
        
        # Show warning if metrics exceed thresholds
        if health_metrics['cpu_usage'] > 80 or health_metrics['memory_usage'] > 80:
            st.warning("System resources are running high!")

    def show_login_page(self):
        """Display the login interface with registration option."""
        if 'page' not in st.session_state:
            st.session_state.page = "login"
            
        if st.session_state.page == "register":
            self.show_registration_page()
            
            # Add a "Back to Login" button
            if st.button("Back to Login"):
                st.session_state.page = "login"
                st.rerun()
                
        else:  # Login page
            st.subheader("Login")
            
            col1, col2 = st.columns(2)
            
            with col1:
                email = st.text_input("Email")
                password = st.text_input("Password", type="password")
                
                if st.button("Login"):
                    if self.authenticate_user(email, password):
                        st.success("Login successful!")
                        st.session_state.logged_in = True
                        st.rerun()
                    else:
                        st.error("Invalid credentials!")
            
            with col2:
                st.write("New student?")
                if st.button("Register as Student"):
                    st.session_state.page = "register"
                    st.rerun()

    def show_registration_page(self):
        self.student_registration.show_registration_form()

    def show_main_interface(self):
        """Display the main interface based on user role."""
        # Sidebar navigation
        self.show_sidebar()
        
        # Main content
        if st.session_state.user_role == "admin":
            self.show_admin_interface()
        else:
            self.show_student_interface()

    def show_sidebar(self):
        """Display the sidebar navigation."""
        with st.sidebar:
            st.title("Navigation")
            
            if st.session_state.user_role == "admin":
                self.show_admin_sidebar()
            else:
                self.show_student_sidebar()
            
            if st.button("Logout"):
                self.logout_user()

    def show_admin_sidebar(self):
        """Display admin sidebar options."""
        pages = {
            "Dashboard": "dashboard",
            "Student Management": "student_management",
            "Programme Management": "programme_management",
            "Document Verification": "verification",
            "Reports": "reports",
            "System Settings": "settings"
        }
        
        selected_page = st.selectbox("Select Page", list(pages.keys()))
        st.session_state.current_page = pages[selected_page]

    def show_student_sidebar(self):
        """Display student sidebar options."""
        pages = {
            "My Profile": "profile",
            "Documents": "documents",
            "Calendar": "calendar",
            "Support": "support"
        }
        
        selected_page = st.selectbox("Select Page", list(pages.keys()))
        st.session_state.current_page = pages[selected_page]

    def show_admin_interface(self):
        """Display the admin interface based on selected page."""
        if st.session_state.current_page == "dashboard":
            self.show_admin_dashboard()
        elif st.session_state.current_page == "student_management":
            self.show_student_management()
        elif st.session_state.current_page == "programme_management":
            self.show_programme_management()
        elif st.session_state.current_page == "verification":
            self.show_verification_page()
        elif st.session_state.current_page == "reports":
            self.show_reports_page()
        elif st.session_state.current_page == "settings":
            self.show_settings_page()

    def show_admin_dashboard(self):
        """Display the admin dashboard."""
        st.header("Admin Dashboard")
        
        # Create columns for metrics
        col1, col2, col3 = st.columns(3)
        
        # Display key metrics
        with col1:
            total_students = self.get_total_students()
            st.metric("Total Students", total_students)
            
        with col2:
            pending_verifications = self.get_pending_verifications()
            st.metric("Pending Verifications", pending_verifications)
            
        with col3:
            active_programmes = self.get_active_programmes()
            st.metric("Active Programmes", active_programmes)
        
        # Show recent activities
        st.subheader("Recent Activities")
        activities = self.get_recent_activities()
        for activity in activities:
            st.write(f"- {activity['description']} ({activity['timestamp']})")
        
        # Show quick actions
        st.subheader("Quick Actions")
        col1, col2 = st.columns(2)
        
        with col1:
            if st.button("Generate Daily Report"):
                self.generate_daily_report()
            
            if st.button("Send Bulk Notifications"):
                self.show_bulk_notification_interface()
                
        with col2:
            if st.button("Backup Database"):
                self.backup_database()
            
            if st.button("Check System Health"):
                self.show_system_health()

    def show_student_management(self):
        """Display the student management interface."""
        st.header("Student Management")
        
        # Search and filter options
        search_term = st.text_input("Search Students")
        programme_filter = st.selectbox(
            "Filter by Programme",
            ["All"] + self.get_all_programmes()
        )
        
        # Get filtered students
        students = self.get_filtered_students(search_term, programme_filter)
        
        # Display students table
        if students.empty:
            st.warning("No students found.")
        else:
            st.dataframe(students)
        
        # Bulk actions
        st.subheader("Bulk Actions")
        if st.button("Export to Excel"):
            self.export_students_data(students)
        
        if st.button("Send Email to Selected"):
            self.show_bulk_email_interface(students)

    def show_programme_management(self):
        """Display the programme management interface."""
        st.header("Programme Management")
        
        # Add new programme
        st.subheader("Add New Programme")
        with st.form("new_programme"):
            programme_name = st.text_input("Programme Name")
            description = st.text_area("Description")
            levels = st.text_input("Levels (comma-separated)")
            
            if st.form_submit_button("Add Programme"):
                self.add_new_programme(programme_name, description, levels)
        
        # Display existing programmes
        st.subheader("Existing Programmes")
        programmes = self.get_all_programmes_details()
        for prog in programmes:
            with st.expander(prog['name']):
                st.write(f"Description: {prog['description']}")
                st.write(f"Levels: {', '.join(prog['levels'])}")
                st.write(f"Total Students: {prog['total_students']}")
                
                if st.button(f"Edit {prog['name']}"):
                    self.show_programme_edit_form(prog)

    def show_verification_page(self):
        """Display the document verification interface."""
        st.header("Document Verification")
        
        # Filter options
        status_filter = st.selectbox(
            "Filter by Status",
            ["All", "Pending", "Verified", "Rejected"]
        )
        
        # Get documents
        documents = self.get_filtered_documents(status_filter)
        
        # Display documents
        for doc in documents:
            with st.expander(f"{doc['student_name']} - {doc['document_type']}"):
                st.write(f"Uploaded: {doc['uploaded_at']}")
                st.write(f"Status: {doc['status']}")
                
                # Show document preview
                st.image(doc['file_path'])
                
                # Verification actions
                col1, col2 = st.columns(2)
                with col1:
                    if st.button(f"Approve {doc['id']}"):
                        self.verify_document(doc['id'], "verified")
                with col2:
                    if st.button(f"Reject {doc['id']}"):
                        self.verify_document(doc['id'], "rejected")

    def show_reports_page(self):
        st.header("Reports")
        
        # Report type selection
        report_type = st.selectbox(
            "Select Report Type",
            [t.value for t in ReportType]
        )
        
        # Date range selection
        col1, col2 = st.columns(2)
        with col1:
            start_date = st.date_input("Start Date")
        with col2:
            end_date = st.date_input("End Date")
        
        # Format selection
        report_format = st.selectbox(
            "Select Format",
            [f.value for f in ReportFormat]
        )
        
        # Additional filters
        filters = {}
        if report_type == ReportType.ENROLLMENT.value:
            programme = st.selectbox("Filter by Programme", ["All"] + self.get_all_programmes())
            if programme != "All":
                filters['programme_id'] = programme
        
        if st.button("Generate Report"):
            try:
                # Convert date inputs to datetime
                start_datetime = datetime.combine(start_date, datetime.min.time())
                end_datetime = datetime.combine(end_date, datetime.max.time())
                
                report = self.reporting_system.generate_report(
                    ReportType(report_type),
                    start_datetime,
                    end_datetime,
                    ReportFormat(report_format),
                    filters
                )
                
                # Handle the report based on format
                if report_format == ReportFormat.PDF.value:
                    st.download_button(
                        "Download PDF Report",
                        report,
                        file_name=f"{report_type}_report.pdf",
                        mime="application/pdf"
                    )
                elif report_format == ReportFormat.EXCEL.value:
                    st.download_button(
                        "Download Excel Report",
                        report,
                        file_name=f"{report_type}_report.xlsx",
                        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                    )
                elif report_format == ReportFormat.CSV.value:
                    st.download_button(
                        "Download CSV Report",
                        report,
                        file_name=f"{report_type}_report.csv",
                        mime="text/csv"
                    )
                else:
                    st.json(json.loads(report))
                    
            except Exception as e:
                st.error(f"Failed to generate report: {str(e)}")

    def show_settings_page(self):
        """Display the system settings interface."""
        st.header("System Settings")
        
        # Email settings
        st.subheader("Email Settings")
        with st.form("email_settings"):
            email_config = self.config_manager.get_email_config()
            smtp_server = st.text_input("SMTP Server", value=email_config.smtp_server)
            smtp_port = st.number_input("SMTP Port", value=email_config.smtp_port)
            sender_email = st.text_input("Sender Email", value=email_config.sender_email)
            
            if st.form_submit_button("Update Email Settings"):
                success = self.config_manager.update_config('email', {
                    'smtp_server': smtp_server,
                    'smtp_port': smtp_port,
                    'sender_email': sender_email
                })
                if success:
                    st.success("Email settings updated successfully!")
                else:
                    st.error("Failed to update email settings")
        
        # Backup settings
        st.subheader("Backup Settings")
        with st.form("backup_settings"):
            backup_frequency = st.selectbox(
                "Backup Frequency",
                ["Daily", "Weekly", "Monthly"]
            )
            backup_time = st.time_input("Backup Time")
            
            if st.form_submit_button("Update Backup Settings"):
                self.update_backup_settings(backup_frequency, backup_time)
        
        # System maintenance
        st.subheader("System Maintenance")
        if st.button("Clear Cache"):
            self.cache_manager.clear()
            st.success("Cache cleared successfully!")
        
        if st.button("Run System Diagnostics"):
            self.run_system_diagnostics()

    def get_all_programmes(self) -> List[str]:
        """
        Get a list of all programme names from the database.
        
        Returns:
            List[str]: List of programme names
        """
        try:
            with self.db_manager.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT name FROM programmes ORDER BY name")
                return [row[0] for row in cursor.fetchall()]
        except Exception as e:
            logging.error(f"Error fetching programmes: {str(e)}")
            return []

    def get_filtered_documents(self, status_filter: str = "All") -> List[Dict[str, Any]]:
        """
        Get filtered document verification records.
        
        Args:
            status_filter (str): Filter documents by status ("All", "Pending", "Verified", "Rejected")
            
        Returns:
            List[Dict[str, Any]]: List of document records with student and verification details
        """
        try:
            with self.db_manager.get_connection() as conn:
                cursor = conn.cursor()
                
                query = """
                    SELECT 
                        d.id,
                        d.document_type,
                        d.file_path,
                        d.status,
                        d.admin_feedback,
                        d.uploaded_at,
                        s.name as student_name,
                        s.email as student_email,
                        p.name as programme_name
                    FROM documents d
                    JOIN students s ON d.student_id = s.id
                    LEFT JOIN programmes p ON s.programme_id = p.id
                    WHERE 1=1
                """
                params = []

                # Add status filter if not "All"
                if status_filter != "All":
                    query += " AND d.status = ?"
                    params.append(status_filter.lower())

                # Order by upload date, most recent first
                query += " ORDER BY d.uploaded_at DESC"

                cursor.execute(query, params)
                
                # Fetch results and convert to list of dictionaries
                columns = [
                    'id', 'document_type', 'file_path', 'status', 'admin_feedback',
                    'uploaded_at', 'student_name', 'student_email', 'programme_name'
                ]
                documents = []
                
                for row in cursor.fetchall():
                    doc = dict(zip(columns, row))
                    
                    # Format date
                    doc['uploaded_at'] = pd.to_datetime(doc['uploaded_at']).strftime('%Y-%m-%d %H:%M')
                    
                    # Add status badge
                    doc['status_badge'] = self._format_document_status(doc['status'])
                    
                    documents.append(doc)
                
                return documents

        except Exception as e:
            logging.error(f"Error fetching filtered documents: {str(e)}")
            return []

    def _format_document_status(self, status: str) -> str:
        """Format document status with color indicator."""
        status_colors = {
            'pending': '🟡',
            'verified': '🟢',
            'rejected': '🔴'
        }
        return f"{status_colors.get(status, '⚪')} {status.title()}"

    def verify_document(self, document_id: int, status: str, feedback: Optional[str] = None) -> bool:
        """
        Update document verification status.
        
        Args:
            document_id (int): ID of the document to verify
            status (str): New status ("verified" or "rejected")
            feedback (str, optional): Admin feedback for the verification
            
        Returns:
            bool: True if verification was successful, False otherwise
        """
        try:
            with self.db_manager.get_connection() as conn:
                cursor = conn.cursor()
                
                # Update document status
                cursor.execute("""
                    UPDATE documents 
                    SET status = ?, 
                        admin_feedback = ?,
                        verified_at = CURRENT_TIMESTAMP,
                        verified_by = ?
                    WHERE id = ?
                """, (status, feedback, st.session_state.user_id, document_id))
                
                # Get student email and document details for notification
                cursor.execute("""
                    SELECT s.email, s.name, d.document_type
                    FROM documents d
                    JOIN students s ON d.student_id = s.id
                    WHERE d.id = ?
                """, (document_id,))
                
                student_email, student_name, document_type = cursor.fetchone()
                
                # Send email notification
                subject = f"Document Verification Update: {document_type}"
                body = f"""
                    Dear {student_name},
                    
                    Your {document_type} has been {status}.
                    
                    {f'Feedback: {feedback}' if feedback else ''}
                    
                    Best regards,
                    Administration
                """
                
                self.email_manager.send_email(student_email, subject, body)
                
                # Log the verification action
                self.log_audit(
                    action="verify_document",
                    description=f"Document {document_id} {status} by {st.session_state.user_name}"
                )
                
                return True

        except Exception as e:
            logging.error(f"Error verifying document: {str(e)}")
            return False

    def get_all_programmes_details(self) -> List[Dict[str, Any]]:
        """
        Get detailed information about all programmes.
        
        Returns:
            List[Dict[str, Any]]: List of dictionaries containing programme details
        """
        try:
            with self.db_manager.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT 
                        p.id,
                        p.name,
                        p.description,
                        COUNT(DISTINCT s.id) as total_students,
                        GROUP_CONCAT(DISTINCT pl.level_name) as levels
                    FROM programmes p
                    LEFT JOIN students s ON p.id = s.programme_id
                    LEFT JOIN programme_levels pl ON p.id = pl.programme_id
                    GROUP BY p.id, p.name, p.description
                    ORDER BY p.name
                """)
                
                columns = ['id', 'name', 'description', 'total_students', 'levels']
                programmes = []
                
                for row in cursor.fetchall():
                    programme = dict(zip(columns, row))
                    programme['levels'] = programme['levels'].split(',') if programme['levels'] else []
                    programmes.append(programme)
                    
                return programmes
                
        except Exception as e:
            logging.error(f"Error fetching programme details: {str(e)}")
            return []

    def get_programme_by_id(self, programme_id: int) -> Optional[Dict[str, Any]]:
        """
        Get detailed information about a specific programme.
        
        Args:
            programme_id (int): The ID of the programme to fetch
            
        Returns:
            Optional[Dict[str, Any]]: Programme details or None if not found
        """
        try:
            with self.db_manager.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT 
                        p.id,
                        p.name,
                        p.description,
                        COUNT(DISTINCT s.id) as total_students,
                        GROUP_CONCAT(DISTINCT pl.level_name) as levels
                    FROM programmes p
                    LEFT JOIN students s ON p.id = s.programme_id
                    LEFT JOIN programme_levels pl ON p.id = pl.programme_id
                    WHERE p.id = ?
                    GROUP BY p.id, p.name, p.description
                """, (programme_id,))
                
                row = cursor.fetchone()
                if row:
                    programme = dict(zip(
                        ['id', 'name', 'description', 'total_students', 'levels'],
                        row
                    ))
                    programme['levels'] = programme['levels'].split(',') if programme['levels'] else []
                    return programme
                return None
                
        except Exception as e:
            logging.error(f"Error fetching programme {programme_id}: {str(e)}")
            return None  
            
    def get_filtered_students(self, search_term: Optional[str] = None, programme_filter: Optional[str] = None) -> pd.DataFrame:
        """
        Get filtered student data based on search term and programme filter.
        
        Args:
            search_term (str, optional): Search term to filter students by name or email
            programme_filter (str, optional): Programme name to filter students
            
        Returns:
            pd.DataFrame: Filtered student data
        """
        try:
            with self.db_manager.get_connection() as conn:
                query = """
                    SELECT 
                        s.id,
                        s.name,
                        s.email,
                        s.phone,
                        p.name as programme,
                        s.level,
                        s.status,
                        s.created_at,
                        COUNT(d.id) as pending_documents
                    FROM students s
                    LEFT JOIN programmes p ON s.programme_id = p.id
                    LEFT JOIN documents d ON s.id = d.student_id AND d.status = 'pending'
                    WHERE 1=1
                """
                params = []

                # Add search filter
                if search_term:
                    query += """ 
                        AND (
                            LOWER(s.name) LIKE LOWER(?)
                            OR LOWER(s.email) LIKE LOWER(?)
                        )
                    """
                    search_pattern = f"%{search_term}%"
                    params.extend([search_pattern, search_pattern])

                # Add programme filter
                if programme_filter and programme_filter != "All":
                    query += " AND p.name = ?"
                    params.append(programme_filter)

                # Group by and order
                query += """
                    GROUP BY 
                        s.id, s.name, s.email, s.phone, 
                        p.name, s.level, s.status, s.created_at
                    ORDER BY s.created_at DESC
                """

                # Execute query and return as DataFrame
                df = pd.read_sql_query(query, conn, params=params)

                # Format dates
                df['created_at'] = pd.to_datetime(df['created_at']).dt.strftime('%Y-%m-%d')

                # Add status badge
                df['status'] = df['status'].apply(self._format_status_badge)

                return df

        except Exception as e:
            logging.error(f"Error getting filtered students: {str(e)}")
            return pd.DataFrame()

    def _format_status_badge(self, status: str) -> str:
        """Format status as a colored badge."""
        status_colors = {
            'active': '🟢',
            'inactive': '🔴',
            'suspended': '🟡'
        }
        return f"{status_colors.get(status, '⚪')} {status}"

    def export_students_data(self, df: pd.DataFrame) -> bytes:
        """
        Export student data to Excel file.
        
        Args:
            df (pd.DataFrame): Student data to export
            
        Returns:
            bytes: Excel file content
        """
        try:
            # Create Excel writer object
            output = io.BytesIO()
            with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
                # Write main data
                df.to_excel(writer, sheet_name='Students', index=False)
                
                # Get workbook and worksheet objects
                workbook = writer.book
                worksheet = writer.sheets['Students']
                
                # Add formats
                header_format = workbook.add_format({
                    'bold': True,
                    'bg_color': '#0066cc',
                    'font_color': 'white'
                })
                
                # Format headers
                for col_num, value in enumerate(df.columns.values):
                    worksheet.write(0, col_num, value, header_format)
                    worksheet.set_column(col_num, col_num, len(str(value)) + 2)

            return output.getvalue()

        except Exception as e:
            logging.error(f"Error exporting student data: {str(e)}")
            raise

    def show_bulk_email_interface(self, students_df: pd.DataFrame):
        """
        Show interface for sending bulk emails to selected students.
        
        Args:
            students_df (pd.DataFrame): DataFrame containing student data
        """
        st.subheader("Send Bulk Email")
        
        with st.form("bulk_email_form"):
            # Email template selection
            template_options = ["Welcome", "Reminder", "Announcement", "Custom"]
            template_type = st.selectbox("Email Template", template_options)
            
            # Email subject and body
            subject = st.text_input("Subject")
            if template_type == "Custom":
                body = st.text_area("Message Body")
            else:
                body = self._get_email_template(template_type)
            
            # Preview email
            if st.checkbox("Preview Email"):
                st.info("Email Preview:")
                st.write(f"Subject: {subject}")
                st.write("Body:")
                st.write(body)
            
            if st.form_submit_button("Send Email"):
                try:
                    # Get recipient emails
                    recipients = students_df['email'].tolist()
                    
                    # Send emails
                    results = self.email_manager.send_bulk_emails(recipients, subject, body)
                    
                    # Show results
                    success_count = sum(1 for v in results.values() if v)
                    st.success(f"Successfully sent {success_count} out of {len(recipients)} emails")
                    
                    if failed_count := len(recipients) - success_count:
                        st.warning(f"Failed to send {failed_count} emails")
                        
                except Exception as e:
                    logging.error(f"Error sending bulk emails: {str(e)}")
                    st.error("Failed to send emails")

    def _get_email_template(self, template_type: str) -> str:
        """Get predefined email template content."""
        templates = {
            "Welcome": """
                Dear Student,
                
                Welcome to our institution! We're excited to have you join us.
                
                Best regards,
                Administration
            """,
            "Reminder": """
                Dear Student,
                
                This is a friendly reminder about your pending documents.
                Please submit them as soon as possible.
                
                Best regards,
                Administration
            """,
            "Announcement": """
                Dear Student,
                
                We have an important announcement regarding your programme.
                Please check your student portal for more details.
                
                Best regards,
                Administration
            """
        }
        return templates.get(template_type, "")
            
            
            
    def get_total_students(self) -> int:
        """Get total number of active students."""
        try:
            with self.db_manager.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM students WHERE status = 'active'")
                return cursor.fetchone()[0]
        except Exception as e:
            logging.error(f"Error getting total students: {str(e)}")
            return 0

    def get_pending_verifications(self) -> int:
        """Get number of pending document verifications."""
        try:
            with self.db_manager.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM documents WHERE status = 'pending'")
                return cursor.fetchone()[0]
        except Exception as e:
            logging.error(f"Error getting pending verifications: {str(e)}")
            return 0

    def get_active_programmes(self) -> int:
        """Get number of active programmes."""
        try:
            with self.db_manager.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM programmes")
                return cursor.fetchone()[0]
        except Exception as e:
            logging.error(f"Error getting active programmes: {str(e)}")
            return 0

    def get_recent_activities(self) -> List[Dict[str, Any]]:
        """Get recent system activities."""
        try:
            with self.db_manager.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT action, description, timestamp 
                    FROM audit_logs 
                    ORDER BY timestamp DESC 
                    LIMIT 10
                """)
                columns = ['action', 'description', 'timestamp']
                return [dict(zip(columns, row)) for row in cursor.fetchall()]
        except Exception as e:
            logging.error(f"Error getting recent activities: {str(e)}")
            return []

    def generate_daily_report(self):
        """Generate and download daily summary report."""
        try:
            # Get today's data
            today = datetime.now().date()
            report = self.reporting_system.generate_report(
                ReportType.ENROLLMENT,
                today,
                today,
                format=ReportFormat.PDF
            )
            
            # Create download link
            st.download_button(
                "Download Report",
                report,
                file_name=f"daily_report_{today}.pdf",
                mime="application/pdf"
            )
        except Exception as e:
            logging.error(f"Error generating daily report: {str(e)}")
            st.error("Failed to generate report")

    def show_bulk_notification_interface(self):
        """Show interface for sending bulk notifications."""
        st.subheader("Send Bulk Notifications")
        
        with st.form("bulk_notification"):
            # Recipient selection
            recipient_type = st.selectbox(
                "Send to",
                ["All Students", "Specific Programme", "Specific Level"]
            )
            
            if recipient_type == "Specific Programme":
                programme = st.selectbox("Select Programme", self.get_all_programmes())
            elif recipient_type == "Specific Level":
                level = st.selectbox("Select Level", ["Level 100", "Level 200", "Level 300", "Level 400"])
            
            # Message content
            title = st.text_input("Notification Title")
            message = st.text_area("Message")
            
            if st.form_submit_button("Send Notification"):
                try:
                    # Get recipient IDs based on selection
                    recipient_ids = self._get_notification_recipients(recipient_type, locals())
                    
                    # Send notification
                    result = self.mobile_integration.send_push_notification(
                        recipient_ids,
                        title,
                        message,
                        NotificationType.INFO
                    )
                    
                    st.success(f"Notification sent to {result['success']} recipients")
                    if result['failure'] > 0:
                        st.warning(f"Failed to send to {result['failure']} recipients")
                        
                except Exception as e:
                    logging.error(f"Error sending bulk notification: {str(e)}")
                    st.error("Failed to send notifications")

    def backup_database(self):
        """Create a backup of the database."""
        try:
            backup_path = self.backup_manager.create_backup()
            st.success(f"Database backup created successfully at {backup_path}")
        except Exception as e:
            logging.error(f"Error creating database backup: {str(e)}")
            st.error("Failed to create database backup")

    def show_system_health(self):
        """Display system health metrics."""
        try:
            metrics = self.system_monitor.check_system_health()
            
            st.subheader("System Health")
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.metric("CPU Usage", f"{metrics['cpu_usage']}%")
            with col2:
                st.metric("Memory Usage", f"{metrics['memory_usage']}%")
            with col3:
                st.metric("Disk Usage", f"{metrics['disk_usage']}%")
                
            # Show warnings for high usage
            for metric, value in metrics.items():
                if value > 80:
                    st.warning(f"High {metric.replace('_', ' ')}: {value}%")
                    
        except Exception as e:
            logging.error(f"Error checking system health: {str(e)}")
            st.error("Failed to check system health")

    def _get_notification_recipients(self, recipient_type: str, params: Dict) -> List[int]:
        """Get recipient IDs based on selection criteria."""
        try:
            with self.db_manager.get_connection() as conn:
                cursor = conn.cursor()
                
                if recipient_type == "All Students":
                    cursor.execute("SELECT id FROM students WHERE status = 'active'")
                elif recipient_type == "Specific Programme":
                    cursor.execute(
                        "SELECT id FROM students WHERE programme_id = ? AND status = 'active'",
                        (params.get('programme'),)
                    )
                elif recipient_type == "Specific Level":
                    cursor.execute(
                        "SELECT id FROM students WHERE level = ? AND status = 'active'",
                        (params.get('level'),)
                    )
                    
                return [row[0] for row in cursor.fetchall()]
                
        except Exception as e:
            logging.error(f"Error getting notification recipients: {str(e)}")
            return []
            
            
    def logout_user(self):
        """Log out the current user by clearing session state."""
        st.session_state.logged_in = False
        st.session_state.user_role = None
        st.session_state.user_id = None
        st.session_state.user_name = None
        st.rerun()

    def show_student_interface(self):
        """Display the student interface based on selected page."""
        if st.session_state.current_page == "profile":
            self.show_student_profile()
        elif st.session_state.current_page == "documents":
            self.show_student_documents()
        elif st.session_state.current_page == "calendar":
            self.show_student_calendar()
        elif st.session_state.current_page == "support":
            self.show_student_support()

    # Add more methods as needed...

if __name__ == "__main__":
    app = MainApp()
    app.run()
