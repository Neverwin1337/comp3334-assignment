# SecureChat Deployment Guide

This guide provides step-by-step instructions to deploy and run the SecureChat application on a clean Windows 11 or Ubuntu Linux system.

## Table of Contents
1. [System Requirements](#system-requirements)
2. [Windows 11 Deployment](#windows-11-deployment)
3. [Ubuntu Linux Deployment](#ubuntu-linux-deployment)
4. [Running the Application](#running-the-application)
5. [Usage Guide](#usage-guide)
6. [Troubleshooting](#troubleshooting)

---

## System Requirements

### Minimum Requirements
- **OS**: Windows 11 or Ubuntu 22.04+
- **RAM**: 4GB minimum
- **Disk**: 500MB free space
- **Network**: Internet connection for package installation

### Software Dependencies
- Python 3.10 or higher
- pip (Python package manager)
- Git (optional, for cloning repository)

---

## Windows 11 Deployment

### Step 1: Install Python

1. Download Python from https://www.python.org/downloads/
2. Run the installer
3. **IMPORTANT**: Check "Add Python to PATH" during installation
4. Click "Install Now"
5. Verify installation by opening Command Prompt (cmd) and running:
   ```cmd
   python --version
   pip --version
   ```

### Step 2: Download the Application

**Option A: Using Git**
```cmd
git clone https://github.com/Neverwin1337/comp3334-assignment.git
cd comp3334-assignment
```

**Option B: Download ZIP**
1. Download the ZIP file from the repository
2. Extract to a folder (e.g., `C:\SecureChat`)
3. Open Command Prompt and navigate to the folder:
   ```cmd
   cd C:\SecureChat
   ```

### Step 3: Set Up Server

```cmd
cd server
pip install -r requirements.txt
```

### Step 4: Initialize Database

```cmd
python init_db.py
```

### Step 5: Set Up Client

Open a new Command Prompt window:
```cmd
cd client
pip install -r requirements.txt
```

### Step 6: Run the Application

**Terminal 1 - Start Server:**
```cmd
cd server
python app.py --skip-otp --no-tls
```

**Terminal 2 - Start Client:**
```cmd
cd client
python main.py --skip-otp
```

---

## Ubuntu Linux Deployment

### Step 1: Update System and Install Dependencies

```bash
sudo apt update
sudo apt upgrade -y
sudo apt install -y python3 python3-pip python3-venv git
```

### Step 2: Install Qt Dependencies (for GUI)

```bash
sudo apt install -y libxcb-xinerama0 libxcb-cursor0 libxkbcommon-x11-0 \
    libxcb-icccm4 libxcb-image0 libxcb-keysyms1 libxcb-randr0 \
    libxcb-render-util0 libxcb-shape0 libegl1 libgl1
```

### Step 3: Download the Application

```bash
git clone https://github.com/Neverwin1337/comp3334-assignment.git
cd comp3334-assignment
```

### Step 4: Create Virtual Environment (Recommended)

```bash
python3 -m venv venv
source venv/bin/activate
```

### Step 5: Set Up Server

```bash
cd server
pip install -r requirements.txt
```

### Step 6: Initialize Database

```bash
python init_db.py
```

### Step 7: Set Up Client

Open a new terminal:
```bash
cd comp3334-assignment
source venv/bin/activate
cd client
pip install -r requirements.txt
```

### Step 8: Run the Application

**Terminal 1 - Start Server:**
```bash
cd server
python app.py --skip-otp --no-tls
```

**Terminal 2 - Start Client:**
```bash
cd client
python main.py --skip-otp
```

---

## Running the Application

### Server Options

| Option | Description |
|--------|-------------|
| `--skip-otp` | Disable OTP verification (for testing) |
| `--no-tls` | Disable TLS encryption (for testing) |

**Production mode (with TLS and OTP):**
```bash
python app.py
```

**Development mode (no TLS, no OTP):**
```bash
python app.py --skip-otp --no-tls
```

### Client Options

| Option | Description |
|--------|-------------|
| `--skip-otp` | Skip OTP verification during login |

```bash
python main.py --skip-otp
```

---

## Usage Guide

### 1. Register a New Account

1. Launch the client application
2. Click "Register" tab
3. Enter username (3-32 characters, alphanumeric and underscore only)
4. Enter password (minimum 8 characters)
5. Click "Register"
6. **Save the QR code** - scan it with an authenticator app (Google Authenticator, Authy, etc.)

### 2. Login

1. Enter your username and password
2. Enter the 6-digit OTP code from your authenticator app (if OTP is enabled)
3. Click "Login"

### 3. Add Friends

1. Go to "Contacts" tab
2. Enter the username of the person you want to add
3. Click the "+" button
4. Wait for them to accept your friend request

### 4. Accept Friend Requests

1. Go to "Requests" tab
2. Click ✓ to accept or ✗ to decline

### 5. Send Messages

1. Click on a friend in "Contacts" or "Chats" tab
2. Type your message
3. (Optional) Check "Self-destruct" and set time for disappearing messages
4. Click "Send"

### 6. View Security Fingerprint

1. Open a chat with a contact
2. Click "🔒 Fingerprint" button
3. Verify the fingerprint matches your contact's device
4. Click "Mark as Verified" if confirmed

### 7. Block/Remove Friends

1. Go to "Contacts" tab
2. Right-click on a friend
3. Select "Remove Friend" or "Block User"

---

## Troubleshooting

### Common Issues

#### "Connection refused" error
- Ensure the server is running
- Check if the server URL is correct (default: `https://localhost:5000`)
- If using `--no-tls`, client connects to `http://localhost:5000`

#### "Invalid credentials" error
- Check username and password
- Ensure the user is registered

#### Qt/GUI errors on Linux
```bash
sudo apt install -y libxcb-xinerama0 libxcb-cursor0
export QT_QPA_PLATFORM=xcb
```

#### SSL Certificate errors
- Use `--no-tls` flag for testing
- Or accept the self-signed certificate warning

#### Database errors
- Delete `server/app.db` and run `python init_db.py` again
- Delete `client/data/*.db` to reset client data

### Log Files

- Server logs are printed to console
- Client data is stored in `client/data/`

---

## Security Notes

For production deployment:
1. **Enable TLS** - Do not use `--no-tls` in production
2. **Enable OTP** - Do not use `--skip-otp` in production
3. **Use strong passwords** - Minimum 8 characters recommended
4. **Verify fingerprints** - Always verify contact fingerprints in person
5. **Keep software updated** - Regularly update dependencies

---

## File Structure

```
comp3334-assignment/
├── client/
│   ├── main.py              # Client entry point
│   ├── api_client.py        # API communication
│   ├── crypto_utils.py      # Cryptographic functions
│   ├── storage.py           # Local SQLite storage
│   ├── widgets.py           # UI components
│   ├── workers.py           # Background polling
│   ├── requirements.txt     # Client dependencies
│   └── data/                # Local data storage
├── server/
│   ├── app.py               # Server entry point
│   ├── config.py            # Server configuration
│   ├── models.py            # Database models
│   ├── init_db.py           # Database initialization
│   ├── requirements.txt     # Server dependencies
│   └── api/
│       ├── auth.py          # Authentication endpoints
│       ├── keys.py          # Key management endpoints
│       ├── friends.py       # Friend management endpoints
│       └── messages.py      # Message endpoints
├── DEPLOYMENT.md            # This file
└── SECURITY_DESIGN.md       # Security documentation
```
