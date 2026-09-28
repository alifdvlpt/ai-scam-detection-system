@echo off
cd /d "%~dp0"
echo Creating Python virtual environment...
python -m venv .venv
call .venv\Scripts\activate
echo Installing requirements...
python -m pip install --upgrade pip
pip install -r requirements.txt
echo Starting application...
streamlit run app.py
pause
