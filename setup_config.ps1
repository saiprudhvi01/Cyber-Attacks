# Create .streamlit directory if it doesn't exist
if (-not (Test-Path -Path .\.streamlit)) {
    New-Item -ItemType Directory -Path .\.streamlit | Out-Null
}

# Create config.toml with the correct settings
@'
[server]
fileWatcherType = "none"
'@ | Out-File -FilePath .\.streamlit\config.toml -Encoding utf8

Write-Host "Streamlit configuration created successfully!"
