# File Deploy

A secure file deployment tool that facilitates file transfers between development and target environments, with support for post-deployment scripting and remote debugging capabilities.

## Features

- Secure file transfer using TLS encryption
- Password authentication for upload protection
- Post-upload script execution
- Remote deployment automation
- Directory structure preservation during transfers
- Cross-platform compatibility (Linux/Windows)

## Prerequisites

- [Rust](https://www.rust-lang.org/) 1.74.0 or later
- [Cargo](https://doc.rust-lang.org/cargo/) (Rust's package manager)

## Compilation

### Building from source

```bash
# Clone the repository
git clone <repository-url>
cd file_deploy

# Build in debug mode
cargo build

# Build in release mode for optimized performance
cargo build --release
```

### Cross-compilation for Windows from Linux

```bash
# Install Windows target
rustup target add x86_64-pc-windows-gnu

# Install Windows linker (on Debian/Ubuntu)
sudo apt install mingw-w64

# Cross-compile for Windows
cargo build --release --target x86_64-pc-windows-gnu
```

The compiled binary will be located at `target/release/file_deploy` (or `target/x86_64-pc-windows-gnu/release/file_deploy.exe` for Windows).

## Usage

### Server Mode

Start a server to receive files:

```bash
file_deploy serv \
  --listen 0.0.0.0:4399 \
  --cert /path/to/server.crt \
  --key /path/to/server.key \
  --password your_secure_password \
  --script /path/to/post_deploy_script.sh \
  /allowed/directory/1 /allowed/directory/2
```

Parameters:
- `--listen`: Address to listen on (default: 0.0.0.0:4399)
- `--cert`: TLS certificate file path (required)
- `--key`: TLS private key file path (required)
- `--password`: Authentication password (required)
- `--script`: Script to execute after file upload (optional)
- Positional arguments: Allowed directories where files can be saved

The server will output its certificate fingerprint, which is needed for client authentication.

### Client Mode

Deploy files to a server:

```bash
file_deploy deploy \
  --server server_ip:4399 \
  --fingerprint server_certificate_fingerprint \
  --password your_secure_password \
  /local/file1:/remote/destination1 /local/directory:/remote/destination
```

Parameters:
- `--server`: Server address (required)
- `--fingerprint`: Server certificate's SHA256 fingerprint (required)
- `--password`: Authentication password (required)
- Positional arguments: Files or directories to upload in format `local_path:remote_path`

## Example: Remote Development and Debugging Workflow

This example demonstrates how to use File Deploy for C/C++ cross-platform development, deploying Windows applications from a Linux development environment.

### Setup

#### 1. Prerequisites

- Linux development machine with VS Code installed
- Windows target machine with network connectivity
- File Deploy compiled for both platforms
- [VS Code C/C++ Extension Package](https://marketplace.visualstudio.com/items?itemName=ms-vscode.cpptools-extension-pack) installed

#### 2. Certificate Generation for Testing

```bash
# Generate a self-signed certificate for testing
mkdir -p test_certs
cd test_certs
openssl req -x509 -newkey rsa:4096 -nodes -keyout server.key -out server.crt -days 365 -subj "/CN=localhost"
cd ..
```

#### 3. Server Setup (on Windows)

```powershell
# Start the server on Windows
.\file_deploy.exe serv --listen 0.0.0.0:4399 --cert .\server.crt --key .\server.key --password secure123 --script .\post_deploy.bat C:\DeployTarget
```

Note the certificate fingerprint displayed when starting the server.

#### 4. Development Workflow (on Linux)

1. Create a Visual Studio Code project for Windows:

```bash
# Create project directory
mkdir -p ~/projects/windows_app
cd ~/projects/windows_app

# Setup a basic C++ Windows application
cat > main.cpp << EOL
#include <windows.h>
#include <iostream>

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    MessageBoxA(NULL, "Hello from Linux-developed app!", "Remote Deploy Demo", MB_OK);
    return 0;
}
EOL

# Create VS Code launch configuration for remote debugging
mkdir -p .vscode
cat > .vscode/launch.json << EOL
{
    "version": "0.2.0",
    "configurations": [
        {
            "name": "(gdb) Launch",
            "type": "cppdbg",
            "request": "launch",
            "program": "enter program name, for example ${workspaceFolder}/a.out",
            "args": [],
            "stopAtEntry": false,
            "cwd": "${fileDirname}",
            "environment": [],
            "externalConsole": false,
            "MIMode": "gdb",
            "miDebuggerServerAddress": "192.168.1.100:1234", 
            "setupCommands": [
                {
                    "description": "Enable pretty-printing for gdb",
                    "text": "-enable-pretty-printing",
                    "ignoreFailures": true
                },
                {
                    "description": "Set Disassembly Flavor to Intel",
                    "text": "-gdb-set disassembly-flavor intel",
                    "ignoreFailures": true
                }
            ]
        }

    ]
}
EOL

# Create build script
cat > build.sh << EOL
#!/bin/bash
x86_64-w64-mingw32-g++ main.cpp -o app.exe -mwindows
EOL
chmod +x build.sh

# Create deployment script
cat > deploy.sh << EOL
#!/bin/bash
WINDOWS_IP="192.168.1.100"  # Replace with your Windows machine IP
CERT_FINGERPRINT="abcdef1234567890"  # Replace with actual fingerprint

# Build the application
./build.sh

# Deploy the application
file_deploy deploy \
  --server \${WINDOWS_IP}:4399 \
  --fingerprint \${CERT_FINGERPRINT} \
  --password secure123 \
  ./app.exe:C:/DeployTarget/app.exe
EOL
chmod +x deploy.sh
```

2. Build and deploy the application:

```bash
# Build and deploy
./deploy.sh
```

3. Create Windows post-deployment script (on Windows target):

```batch
@echo off
REM This is post_deploy.bat on the Windows machine
echo Starting application...
C:\path\to\gdbserver\gdbserver.exe localhost:1234 C:\DeployTarget\app.exe
```

4. Debug the application remotely using VS Code's remote debugging features.

## Dependencies

This project uses the following open-source libraries:

- [tokio](https://github.com/tokio-rs/tokio) - Asynchronous runtime for Rust
- [clap](https://github.com/clap-rs/clap) - Command-line argument parser
- [rustls](https://github.com/rustls/rustls) - TLS implementation in Rust
- [prost](https://github.com/tokio-rs/prost) - Protocol Buffers implementation
- [sha2](https://github.com/RustCrypto/hashes) - SHA-2 hash functions
- [tokio-rustls](https://github.com/tokio-rs/tls) - Tokio TLS integration
- [crc32c](https://github.com/zowens/crc32c) - CRC32C implementation
- [x509-parser](https://github.com/rusticata/x509-parser) - X.509 certificate parser

## License

You may use this code under either the [Apache 2.0 license](https://www.apache.org/licenses/LICENSE-2.0)
or the [MIT license](https://opensource.org/licenses/MIT), at your option.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
