@echo off
echo ============================================
echo  PHANTOM - Installing Dependencies
echo ============================================
echo.

pip install google-generativeai chromadb python-dotenv requests rich flask shodan bandit python-nmap 2>&1

echo.
echo ============================================
echo  Installation complete!
echo  Now run: python main.py 127.0.0.1 ./target_app
echo ============================================
pause
