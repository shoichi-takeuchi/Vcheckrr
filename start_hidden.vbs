' start_hidden.vbs
' ウィンドウを表示せずにバックグラウンドで起動するVBScript
' スタートアップ登録や常駐起動に使用する

Set oShell = CreateObject("WScript.Shell")
Dim scriptDir
scriptDir = Left(WScript.ScriptFullName, InStrRev(WScript.ScriptFullName, "\"))

' Pythonスクリプトをウィンドウなしで実行 (0 = 非表示)
oShell.Run "python """ & scriptDir & "main.py""", 0, False

Set oShell = Nothing
