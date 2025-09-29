#!/bin/bash
# Create .streamlit directory if it doesn't exist
mkdir -p .streamlit

# Create config.toml with the correct settings
cat > .streamlit/config.toml <<EOL
[server]
fileWatcherType = "none"
EOL

echo "Streamlit configuration created successfully!"
