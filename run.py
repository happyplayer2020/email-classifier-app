#!/usr/bin/env python3
"""
Email Classifier Application Runner
"""

import os
import sys
from app import app

def main():
    """Main function to run the Flask application"""
    
    # Check if OpenAI API key is set
    if not os.getenv('OPENAI_API_KEY'):
        print("❌ Error: OPENAI_API_KEY environment variable is not set!")
        print("Please set your OpenAI API key:")
        print("1. Create a .env file in the project root")
        print("2. Add: OPENAI_API_KEY=your_api_key_here")
        print("3. Or set the environment variable directly")
        sys.exit(1)
    
    print("🚀 Starting Email Classifier Application...")
    print("📧 AI-powered email classification using OpenAI")
    print("🌐 Web interface available at: http://localhost:5000")
    print("🔧 API endpoints:")
    print("   - POST /api/classify - Classify email content")
    print("   - GET  /api/categories - Get available categories")
    print("   - GET  /health - Health check")
    print("\nPress Ctrl+C to stop the server")
    
    try:
        app.run(debug=True, host='127.0.0.1', port=3000)
    except KeyboardInterrupt:
        print("\n👋 Shutting down Email Classifier...")
    except Exception as e:
        print(f"❌ Error starting application: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
