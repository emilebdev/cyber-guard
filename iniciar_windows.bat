@echo off
title CyberGuard - Inicializador
cd /d "%~dp0"

if not exist "venv\Scripts\python.exe" (
    echo Criando ambiente virtual...
    python -m venv venv
)

echo Instalando ou atualizando dependencias...
call venv\Scripts\python.exe -m pip install -r requirements.txt

if not exist ".env" (
    copy ".env.example" ".env" >nul
    echo Arquivo .env criado a partir do exemplo.
)

echo.
echo Iniciando CyberGuard...
echo Acesse: http://127.0.0.1:5000
echo Para encerrar, pressione CTRL+C nesta janela.
echo.
call venv\Scripts\python.exe app.py
pause
