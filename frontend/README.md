# CyberAgent Frontend

Modern, aesthetic frontend for the dataset generator.

## Quick Start

```bash
# Install dependencies
pip install -r frontend/requirements.txt

# Run server
python frontend/server.py

# Open http://localhost:8000
```

## Features

- Dark theme with accent green highlights
- URL and file input modes
- Drag-and-drop style interface
- Real-time progress
- JSONL download
- HuggingFace upload

## API Endpoints

- `POST /api/generate` - Generate trajectories
- `POST /api/upload-hf` - Upload to HuggingFace