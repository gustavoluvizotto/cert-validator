# https://lazyadmin.nl/powershell/how-to-create-a-powershell-scheduled-task
$Time = New-ScheduledTaskTrigger -At 10:00 -Weekly -DaysOfWeek Monday
$PS = New-ScheduledTaskAction -Execute "PowerShell" -Argument '-NoProfile -ExecutionPolicy Bypass -File "C:\Users\gusta\workspace\cert-validator\rootstores\collect\windows-rootstore.ps1"' -WorkingDirectory 'C:\Users\gusta\workspace\cert-validator'
Register-ScheduledTask -TaskName "rootstores-collect" -Trigger $Time -Action $PS

