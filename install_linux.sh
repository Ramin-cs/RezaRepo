#!/bin/bash
echo "🚀 ARAT Cross-Platform Installer for Linux/macOS"
echo "================================================"

# Detect OS
if [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
    echo "🍎 Detected macOS"
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
    echo "🐧 Detected Linux"
else
    echo "❌ Unsupported OS: $OSTYPE"
    exit 1
fi

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to install packages
install_packages() {
    echo "📦 Installing system packages..."
    
    if [[ "$OS" == "macos" ]]; then
        # macOS with Homebrew
        if command_exists brew; then
            echo "📦 Installing packages via Homebrew..."
            brew install git go python3
        else
            echo "❌ Homebrew not found. Please install Homebrew first:"
            echo "   /bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\""
            exit 1
        fi
        
    elif [[ "$OS" == "linux" ]]; then
        # Linux - try different package managers
        if command_exists apt; then
            echo "📦 Installing packages via apt (Ubuntu/Debian)..."
            sudo apt update
            sudo apt install -y git golang-go python3 python3-pip
            
        elif command_exists yum; then
            echo "📦 Installing packages via yum (CentOS/RHEL)..."
            sudo yum update -y
            sudo yum install -y git golang python3 python3-pip
            
        elif command_exists pacman; then
            echo "📦 Installing packages via pacman (Arch Linux)..."
            sudo pacman -S --noconfirm git go python python-pip
            
        else
            echo "❌ No supported package manager found"
            exit 1
        fi
    fi
}

# Function to install Python packages
install_python_packages() {
    echo "🐍 Installing Python packages..."
    
    if command_exists pip3; then
        pip3 install sublist3r python-whois --user
    elif command_exists pip; then
        pip install sublist3r python-whois --user
    else
        echo "❌ pip not found"
        exit 1
    fi
}

# Function to install Go tools
install_go_tools() {
    echo "🔧 Installing Go tools..."
    
    if ! command_exists go; then
        echo "❌ Go not found. Please install Go first."
        exit 1
    fi
    
    # Set up Go environment
    export GOPATH="$HOME/go"
    export PATH="$PATH:$GOPATH/bin"
    
    # Install tools
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest
    go install github.com/OJ/gobuster/v3@latest
    go install github.com/projectdiscovery/katana/cmd/katana@latest
    go install github.com/projectdiscovery/gospider/cmd/gospider@latest
}

# Function to setup environment
setup_environment() {
    echo "🔧 Setting up environment..."
    
    # Add to shell profile
    SHELL_PROFILE=""
    if [[ -f "$HOME/.bashrc" ]]; then
        SHELL_PROFILE="$HOME/.bashrc"
    elif [[ -f "$HOME/.zshrc" ]]; then
        SHELL_PROFILE="$HOME/.zshrc"
    elif [[ -f "$HOME/.profile" ]]; then
        SHELL_PROFILE="$HOME/.profile"
    fi
    
    if [[ -n "$SHELL_PROFILE" ]]; then
        echo "📝 Adding PATH to $SHELL_PROFILE"
        
        # Check if PATH already exists
        if ! grep -q "ARAT Tools PATH" "$SHELL_PROFILE"; then
            cat >> "$SHELL_PROFILE" << 'EOF'

# ARAT Tools PATH
export PATH="$PATH:$HOME/go/bin:$HOME/.local/bin"
EOF
        fi
    fi
}

# Function to verify installation
verify_installation() {
    echo "🔍 Verifying installation..."
    
    local all_installed=true
    
    # Check tools
    tools=("git" "go" "python3" "pip3" "sublist3r" "subfinder" "httpx" "gobuster")
    
    for tool in "${tools[@]}"; do
        if command_exists "$tool"; then
            echo "  ✅ $tool is available"
        else
            echo "  ❌ $tool is not available"
            all_installed=false
        fi
    done
    
    return $all_installed
}

# Main installation process
main() {
    echo "📁 Installation directory: $HOME/ARAT_Tools"
    mkdir -p "$HOME/ARAT_Tools"
    
    # Install everything
    install_packages
    install_python_packages
    install_go_tools
    setup_environment
    
    # Verify installation
    if verify_installation; then
        echo ""
        echo "🎉 All tools installed successfully!"
        echo "🔄 Please restart your terminal for PATH changes to take effect."
        echo ""
        echo "To restart your shell:"
        echo "  source ~/.bashrc  # or ~/.zshrc"
        echo ""
    else
        echo ""
        echo "⚠️ Some tools may not be installed correctly."
        echo "Please check the installation manually."
        echo ""
    fi
}

# Run main function
main