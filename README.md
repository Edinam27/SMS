# Professional Programmes Management System

A comprehensive web-based system for managing professional educational programmes, built with Python and Streamlit. This system provides robust features for both administrators and students, facilitating efficient programme management, document verification, and student support.

## 🌟 Features

### For Administrators
- **Dashboard Analytics**: Real-time insights into student enrollment, document verification status, and programme performance
- **Student Management**: Comprehensive tools for managing student records and academic progress
- **Document Verification**: Streamlined process for verifying student documents with automated notifications
- **Programme Management**: Tools for creating and managing educational programmes
- **Reporting System**: Generate detailed reports with customizable parameters and multiple export formats
- **System Settings**: Configure email, backup, and system parameters

### For Students
- **Document Submission**: Easy upload and tracking of required documents
- **Profile Management**: Update personal information and track academic progress
- **Calendar Integration**: Access to programme schedules and important dates
- **Support System**: Integrated helpdesk with automated and human support options

## 🚀 Getting Started

### Prerequisites
```bash
python >= 3.8
streamlit >= 1.0.0
sqlite3
pandas
plotly
Copy
Insert

Installation
Clone the repository:
git clone https://github.com/yourusername/professional-programmes-management.git
cd professional-programmes-management

Install required packages:
pip install -r requirements.txt

Set up environment variables:
cp .env.example .env
# Edit .env with your configuration

Initialize the database:
python init_db.py

Run the application:
streamlit run app.py

🛠️ Configuration
Email Settings
Configure email settings in config/email.yaml:

smtp_server: smtp.gmail.com
smtp_port: 587
sender_email: your-email@domain.com

Security Settings
Configure security parameters in config/security.yaml:

jwt_secret: your-secret-key
session_timeout: 30
max_login_attempts: 3

📊 Database Schema
The system uses SQLite with the following main tables:

students: Student records and academic information
programmes: Programme definitions and details
documents: Document management and verification status
administrators: Admin user management
audit_logs: System activity tracking
🔒 Security Features
JWT-based authentication
Rate limiting for API calls
Document verification with audit trails
Encrypted password storage
Session management
Two-factor authentication support
📱 Mobile Integration
The system includes mobile integration features:

Push notifications
Mobile-responsive interface
Real-time updates
Document upload from mobile devices
📈 Reporting Capabilities
Generate various reports including:

Enrollment statistics
Document verification status
Programme performance metrics
Financial reports
Custom reports with filtering options
🤝 Contributing
Fork the repository
Create your feature branch (git checkout -b feature/AmazingFeature)
Commit your changes (git commit -m 'Add some AmazingFeature')
Push to the branch (git push origin feature/AmazingFeature)
Open a Pull Request
📝 License
This project is licensed under the MIT License - see the LICENSE.md file for details.

🙏 Acknowledgments
Streamlit team for the amazing framework
Contributors and testers
Educational institutions for valuable feedback
📞 Support
For support and queries:

Create an issue in the repository
Contact: support@example.com
Documentation: Wiki
🔄 System Requirements
Minimum Requirements
CPU: 2 cores
RAM: 4GB
Storage: 10GB
Internet connection: 1Mbps
Recommended Requirements
CPU: 4 cores
RAM: 8GB
Storage: 20GB
Internet connection: 5Mbps
🚦 Status
Project is: in active development