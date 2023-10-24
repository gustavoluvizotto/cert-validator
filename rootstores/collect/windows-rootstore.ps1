# See this if required to convert sst to der: https://stackoverflow.com/questions/14532383/pem-file-from-microsoft-serialized-store-sst-files

mkdir -Force shared_dir\windows-rootstore

# https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil
certutil.exe -syncWithWU .\shared_dir\windows-rootstore\

Compress-Archive -Path .\shared_dir\windows-rootstore\* -DestinationPath .\shared_dir\windows-rootstore.zip -Force

podman run --net=host --rm -v shared_dir:/app/shared_dir rootstores-collect --collect-windows

rm -Recurse -Force .\shared_dir\windows-rootstore\
rm -Force .\shared_dir\windows-rootstore.zip

