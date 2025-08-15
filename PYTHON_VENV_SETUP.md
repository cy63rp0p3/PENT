# Python Virtual Environment Setup

This project uses a Python virtual environment to manage dependencies and avoid conflicts with your system Python installation.

## Quick Setup

### Option 1: Using the Setup Script (Recommended)

1. **Run the setup script:**
   ```bash
   # For Command Prompt (Windows)
   setup-python-venv.bat
   
   # For PowerShell (Windows)
   .\setup-python-venv.ps1
   ```

2. **Start the application:**
   ```bash
   start-all.bat
   ```

### Option 2: Manual Setup

1. **Navigate to the backend directory:**
   ```bash
   cd backend
   ```

2. **Create a virtual environment:**
   ```bash
   python -m venv venv
   ```

3. **Activate the virtual environment:**
   ```bash
   # Windows Command Prompt
   venv\Scripts\activate.bat
   
   # Windows PowerShell
   venv\Scripts\Activate.ps1
   
   # Linux/Mac
   source venv/bin/activate
   ```

4. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

5. **Run Django migrations:**
   ```bash
   python manage.py migrate
   ```

6. **Start the Django server:**
   ```bash
   python manage.py runserver
   ```

## Using the Virtual Environment

### Activating the Environment

- **Command Prompt:** `venv\Scripts\activate.bat`
- **PowerShell:** `venv\Scripts\Activate.ps1`
- **Linux/Mac:** `source venv/bin/activate`

### Deactivating the Environment

```bash
deactivate
```

### Common Django Commands

```bash
# Run the development server
python manage.py runserver

# Run migrations
python manage.py migrate

# Create a superuser
python manage.py createsuperuser

# Collect static files
python manage.py collectstatic

# Run tests
python manage.py test
```

## Troubleshooting

### Python Not Found
If you get "Python not found" error:
1. Download and install Python from https://www.python.org/downloads/
2. Make sure to check "Add Python to PATH" during installation
3. Restart your terminal/command prompt

### Virtual Environment Issues
If the virtual environment doesn't activate:
1. Make sure you're in the `backend` directory
2. Try recreating the virtual environment:
   ```bash
   rmdir /s venv
   python -m venv venv
   ```

### Permission Issues
If you get permission errors:
1. Make sure you're not running as administrator
2. Try running the script from a regular user account

### Dependencies Installation Issues
If pip install fails:
1. Upgrade pip: `python -m pip install --upgrade pip`
2. Try installing packages one by one to identify the problematic package
3. Check if you have the required build tools for packages like `cryptography`

## Project Structure

```
pent-framework/
├── backend/
│   ├── venv/              # Virtual environment
│   ├── requirements.txt    # Python dependencies
│   ├── manage.py          # Django management script
│   └── ...
├── setup-python-venv.bat  # Windows setup script
├── setup-python-venv.ps1  # PowerShell setup script
├── activate-venv.bat      # Quick activation script
└── start-all.bat          # Complete application startup
```

## Dependencies

The project uses the following main Python packages:
- Django 4.2.7 - Web framework
- Django REST Framework 3.14.0 - API framework
- python-nmap 0.7.1 - NMAP integration
- requests 2.31.0 - HTTP library
- cryptography 41.0.7 - Security library
- reportlab 4.0.4 - PDF generation

See `backend/requirements.txt` for the complete list.

## Starting the Complete Application

The `start-all.bat` script will:
1. Check and start NMAP
2. Start ZAP daemon
3. Activate the virtual environment
4. Start Django backend
5. Start Next.js frontend

Run it from the project root:
```bash
start-all.bat
```

## Development Workflow

1. **Activate the virtual environment:**
   ```bash
   cd backend
   venv\Scripts\activate.bat
   ```

2. **Make your changes to the Django code**

3. **Test your changes:**
   ```bash
   python manage.py runserver
   ```

4. **Deactivate when done:**
   ```bash
   deactivate
   ```

## Notes

- The virtual environment is stored in `backend/venv/`
- Always activate the virtual environment before running Django commands
- The `start-all.bat` script automatically handles virtual environment activation
- If you need to install additional packages, activate the virtual environment first, then use `pip install package_name` 