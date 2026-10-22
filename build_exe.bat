@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo === Сборка VLAN-Scanner.exe ===
python -m pip install --upgrade pyinstaller || goto :error
python -m PyInstaller --noconfirm --clean --onefile --noconsole --name VLAN-Scanner vlan_scanner.py || goto :error
echo.
echo Готово: %~dp0dist\VLAN-Scanner.exe
pause
exit /b 0
:error
echo.
echo ОШИБКА сборки
pause
exit /b 1
