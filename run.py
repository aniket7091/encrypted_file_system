"""
SecureShare Application Entry Point
Run this file to start the Flask development server
"""

from app import create_app

app = create_app()

if __name__ == '__main__':
    print("\n" + "="*60)
    print("🔐 SecureShare - Multi-Algorithm File Encryption System")
    print("="*60)
    print("\nStarting server...")
    print("Access the application at: http://localhost:5001")
    print("\nPress CTRL+C to stop the server\n")
    
    app.run(debug=True, host='0.0.0.0', port=5001)
