@echo off
rem batver - ver's text: the lines around it and the version in brackets
rem as captured; the product's name before it is masked (F2K's banner
rem names F2K where Windows 2000's names Microsoft Windows 2000).
ver
echo ERRORLEVEL after ver: %ERRORLEVEL%
