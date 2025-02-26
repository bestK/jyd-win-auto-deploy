@echo off
:: 设置代码页为 UTF-8
chcp 65001 > nul
setlocal

:: 编译 Linux 版本
echo 正在编译 Linux 版本...
set GOOS=linux
set GOARCH=amd64
set CGO_ENABLED=0
go build -o autoupdater main.go
if %ERRORLEVEL% EQU 0 (
    echo Linux 版本编译成功！
    echo 正在使用 UPX 压缩 Linux 版本...
    upx --best --lzma autoupdater
)

:: 编译 Windows 版本
echo 正在编译 Windows 版本...
set GOOS=windows
set GOARCH=amd64
set CGO_ENABLED=0
go build -o autoupdater.exe main.go
if %ERRORLEVEL% EQU 0 (
    echo Windows 版本编译成功！
    echo 正在使用 UPX 压缩 Windows 版本...
    upx --best --lzma autoupdater.exe
)

:: 恢复默认环境变量
set GOOS=
set GOARCH=
set CGO_ENABLED=
