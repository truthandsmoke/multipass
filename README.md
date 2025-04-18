# MultiPass

A secure multi-language password management system that accepts symbols from all keyboarded languages simultaneously.

## Features

- Support for multi-language characters in passwords
- Secure password hashing
- Modern, responsive UI
- User authentication system

## Setup

1. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Run the application:
```bash
python app.py
```

4. Visit http://localhost:5000 in your browser

## Test Account

A test account has been created with the following credentials:
- Username: beggarbillionaire
- Password: てƊΐƍل仯‧∌Є⛯ঌ∟ϳ⚉⋡םц⋣बҹʁĐ⛨공ڂʥٲŰжjƑゐ亏ข۩⚋ॠŻ걂֖乹⚾Ӄ‧ӀĆəڶÜ걹ƀڪЛĉׯږǻЕƯ∴ɋね∉s

## Security

- Passwords are securely hashed using Werkzeug's security functions
- Session management is handled by Flask-Login
- SQLite database for user storage 