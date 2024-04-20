param (
    [string]$FileUrl
)

# Download the file content from the URL
$content = Invoke-WebRequest -Uri $FileUrl

# Extract the filename from the URL
$fileName = [System.IO.Path]::GetFileName($FileUrl)

# Save the downloaded content to a temporary file
$tempFilePath = Join-Path -Path $env:TEMP -ChildPath $fileName
$content.Content | Out-File -FilePath $tempFilePath -Encoding utf8

# Copy the content of the downloaded file to the clipboard
$content = Get-Content $tempFilePath
$content | Set-Clipboard

# Remove the temporary file
Remove-Item -Path $tempFilePath

Write-Output "Content from $FileUrl copied to clipboard."
