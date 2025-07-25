#!/usr/bin/env python3
"""
Setup script for Email Classifier
"""

import os
import sys

def create_env_file():
    """Create .env file with user input"""
    print("🔧 Setting up Email Classifier...")
    print("=" * 50)
    
    # Check if .env already exists
    if os.path.exists('.env'):
        print("⚠️  .env file already exists!")
        overwrite = input("Do you want to overwrite it? (y/N): ").lower()
        if overwrite != 'y':
            print("Setup cancelled.")
            return
    
    # Get OpenAI API key
    print("\n📝 Please enter your OpenAI API key:")
    print("You can get your API key from: https://platform.openai.com/api-keys")
    api_key = input("OpenAI API Key: ").strip()
    
    if not api_key:
        print("❌ API key is required!")
        return
    
    # Create .env file
    env_content = f"""# Email Classifier Environment Variables
# Generated by setup.py

# OpenAI API Key
OPENAI_API_KEY={api_key}

# Flask Configuration
FLASK_ENV=development
FLASK_DEBUG=1
"""
    
    try:
        with open('.env', 'w') as f:
            f.write(env_content)
        print("✅ .env file created successfully!")
    except Exception as e:
        print(f"❌ Error creating .env file: {e}")
        return
    
    print("\n🎉 Setup complete!")
    print("You can now run the application with: python run.py")

def check_dependencies():
    """Check if all dependencies are installed"""
    print("🔍 Checking dependencies...")
    
    required_packages = [
        'flask',
        'flask-cors', 
        'openai',
        'python-dotenv',
        'requests'
    ]
    
    missing_packages = []
    
    for package in required_packages:
        try:
            __import__(package.replace('-', '_'))
        except ImportError:
            missing_packages.append(package)
    
    if missing_packages:
        print(f"❌ Missing packages: {', '.join(missing_packages)}")
        print("Please install them with: pip install -r requirements.txt")
        return False
    else:
        print("✅ All dependencies are installed!")
        return True

def main():
    """Main setup function"""
    print("🚀 Email Classifier Setup")
    print("=" * 50)
    
    # Check dependencies
    if not check_dependencies():
        sys.exit(1)
    
    # Create .env file
    create_env_file()
    
    print("\n📚 Next steps:")
    print("1. Make sure your OpenAI API key is valid")
    print("2. Run the application: python run.py")
    print("3. Open your browser to: http://localhost:5000")
    print("4. Try the example emails to test the classifier!")

if __name__ == '__main__':
    main() 