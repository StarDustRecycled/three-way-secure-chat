@echo off
echo Starting Secure Three-Way Chat System Demo
echo.

:: Check if Python is installed
python --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo Error: Python is not installed or not in PATH
    echo Please install Python and try again
    pause
    exit /b 1
)

:: Check if certificates exist, if not run setup.py
if not exist "certs\root_ca_cert.json" (
    echo Certificates not found. Running setup.py to generate certificates...
    python setup.py
    if %ERRORLEVEL% NEQ 0 (
        echo Error: Failed to generate certificates
        pause
        exit /b 1
    )
    echo Certificates generated successfully
    echo.
)

:: Start the server in a new window
echo Starting server...
start "Secure Chat Server" cmd /k "python server.py"

:: Wait for server to initialize
echo Waiting for server to initialize...
timeout /t 3 /nobreak >nul

:: Start the clients in separate windows
echo Starting Client A...
start "Client A" cmd /k "python client.py A"

:: Wait a moment before starting next client
timeout /t 2 /nobreak >nul

echo Starting Client B...
start "Client B" cmd /k "python client.py B"

:: Wait a moment before starting next client
timeout /t 2 /nobreak >nul

echo Starting Client C...
start "Client C" cmd /k "python client.py C"

echo.
echo All components started successfully!
echo You can now chat between the three clients.
echo To exit, type 'exit' or 'quit' in each client window and close this window.
echo.
pause