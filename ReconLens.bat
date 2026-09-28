@echo off
rem "<nul" matters: without it chcp swallows the rest of the input stream.
chcp 65001 >nul <nul
setlocal EnableDelayedExpansion
cd /d "%~dp0"
title ReconLens
set empty=0

rem --- First run: create the virtual environment and install the tool ---
if not exist ".venv\Scripts\reconlens.exe" (
    echo Первый запуск: устанавливаю ReconLens, это займёт около минуты...
    where python >nul 2>nul || (
        echo.
        echo Python не найден. Установи Python 3.10+ с https://www.python.org/downloads/
        echo и при установке поставь галочку "Add Python to PATH".
        pause
        exit /b 1
    )
    python -m venv .venv || goto :install_failed
    ".venv\Scripts\python.exe" -m pip install -q --disable-pip-version-check -e . || goto :install_failed
)

:menu
cls
echo.
echo   ======================================
echo              R e c o n L e n s
echo         пассивная OSINT-разведка
echo   ======================================
echo.
echo   1  Проверить сайт (домен)
echo   2  Найти никнейм на площадках
echo   3  Пробить телефон (офлайн)
echo   4  Проверить e-mail
echo   5  Открыть папку с отчётами
echo   6  Запустить автотесты
echo   0  Выход
echo.
set "choice="
set /p "choice=  Выбери пункт и нажми Enter: "
if defined choice goto :dispatch
rem Nothing entered. If this keeps happening the input stream is closed: stop looping.
set /a empty=empty+1
if %empty% GEQ 5 exit /b 0
goto :menu

:dispatch
set empty=0
if "!choice!"=="1" goto :domain
if "!choice!"=="2" goto :username
if "!choice!"=="3" goto :phone
if "!choice!"=="4" goto :email
if "!choice!"=="5" goto :reports
if "!choice!"=="6" goto :tests
if "!choice!"=="0" exit /b 0
goto :menu

:domain
echo.
echo   Проверяй только свои сайты или тестовые: example.com, expired.badssl.com
echo.
set "target="
set /p "target=  Домен или ссылка: "
if not defined target goto :menu
echo.
".venv\Scripts\reconlens.exe" domain "!target!"
echo.
echo   Отчёт открыт в браузере и сохранён в папке reports.
pause
goto :menu

:username
echo.
set "nick="
set /p "nick=  Никнейм: "
if not defined nick goto :menu
echo.
".venv\Scripts\reconlens.exe" username "!nick!"
echo.
pause
goto :menu

:phone
echo.
echo   Введи номер с кодом страны, например +7 900 123 45 67
echo   Работает офлайн, никуда не отправляет номер.
echo.
set "num="
set /p "num=  Номер телефона: "
if not defined num goto :menu
echo.
".venv\Scripts\reconlens.exe" phone "!num!"
echo.
pause
goto :menu

:email
echo.
set "mail="
set /p "mail=  E-mail адрес: "
if not defined mail goto :menu
echo.
".venv\Scripts\reconlens.exe" email "!mail!"
echo.
pause
goto :menu

:reports
if not exist reports mkdir reports
start "" explorer "%~dp0reports"
goto :menu

:tests
echo.
if not exist ".venv\Scripts\pytest.exe" (
    ".venv\Scripts\python.exe" -m pip install -q --disable-pip-version-check -e ".[dev]"
)
".venv\Scripts\python.exe" -m pytest -q
echo.
pause
goto :menu

:install_failed
echo.
echo Не получилось установить зависимости. Проверь интернет и попробуй ещё раз.
pause
exit /b 1
