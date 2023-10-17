# See this if required to convert sst to der: https://stackoverflow.com/questions/14532383/pem-file-from-microsoft-serialized-store-sst-files

mkdir -Force windows-rootstore

# https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil
certutil.exe -syncWithWU .\windows-rootstore\

Compress-Archive -Path .\windows-rootstore\* -DestinationPath windows-rootstore.zip -Force
