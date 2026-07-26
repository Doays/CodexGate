$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root
python -m uvicorn app.main:app --host 127.0.0.1 --port 8787 --reload
