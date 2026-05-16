#!/usr/bin/env python3
"""
Backend API server for the CyberAgent frontend.
Serves the frontend and handles generation requests.
"""

import os
import sys
import json
import logging
from pathlib import Path
from typing import Optional
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# =============================================================================
# REQUEST MODELS
# =============================================================================

class GenerateRequest(BaseModel):
    groq_key: str
    urls: list[str] = []
    files: list[str] = []
    output_file: str = "trajectories.jsonl"


class UploadRequest(BaseModel):
    hf_token: str
    repo_id: str
    trajectories: list[dict]


# =============================================================================
# GENERATION LOGIC
# =============================================================================

def generate_trajectories(
    groq_key: str,
    urls: list[str] = None,
    files: list[str] = None,
    output_file: str = "trajectories.jsonl"
) -> list[dict]:
    """Generate trajectories using Groq API."""
    
    # Import Groq after checking key
    try:
        import groq
    except ImportError:
        raise HTTPException(status_code=500, detail="Groq package not installed")
    
    # Initialize Groq client
    client = groq.Groq(api_key=groq_key)
    model = "llama3-70b-8192"
    
    trajectories = []
    total = len(urls) + len(files) if urls else (len(files) if files else 0)
    processed = 0
    
    # System prompt
    system_prompt = """You are a dataset generator for training autonomous penetration testing agents.
Your task is to convert hacking walkthroughs into conversational trajectories in ReAct format.

CONVERSATIONAL FORMAT:
User:
You are a black-box penetration testing agent.
Available actions: [{"name": "nmap", "description": "scan ports"}, {"name": "gobuster", "description": "directory brute-force"}, {"name": "sqlmap", "description": "SQL injection"}, {"name": "curl", "description": "make HTTP request"}, {"name": "hydra", "description": "password brute-force"}]
Instruction: <instruction>
Observation: <current state>

Agent:
Thought: <why this action>
Action: <tool[parameters]>

User:
Observation: <tool output>

... (repeat until shell obtained or end of walkthrough)

REQUIREMENTS:
1. The conversation must be LONG and COMPLETE (8-20+ turns)
2. Include realistic FAILURES, RETRIES, and PIVOTS 
3. Generate plausible "Thought" reasoning for each action
4. Include tool outputs that match what the real tool would produce
5. Use realistic target IPs, ports, and findings

Generate a valid JSON object with this structure:
{"id": "unique_id", "conversations": [{"role": "user/assistant", "content": "..."}], "metadata": {"source": "...", "category": "...", "success": true/false}}

Output ONLY valid JSON, no markdown formatting.
"""
    
    def process_source(source: str) -> Optional[dict]:
        """Process a single source."""
        try:
            import requests
            from bs4 import BeautifulSoup
            import trafilatura
            import hashlib
            from datetime import datetime
            
            # Fetch content
            logger.info(f"Fetching: {source}")
            
            if source.startswith(('http://', 'https://')):
                # URL - fetch and extract
                extracted = trafilatura.extract(
                    source,
                    include_tables=False,
                    include_images=False,
                    include_links=False
                )
                
                if not extracted or len(extracted) < 200:
                    response = requests.get(source, timeout=30)
                    response.raise_for_status()
                    soup = BeautifulSoup(response.text, 'lxml')
                    
                    for unwanted in soup(['script', 'style', 'nav', 'footer', 'header']):
                        unwanted.decompose()
                    
                    content = soup.get_text(separator='\n', strip=True)
                else:
                    content = extracted
            else:
                # Local file
                path = Path(source)
                if path.exists():
                    content = path.read_text(encoding='utf-8')
                else:
                    return None
            
            if not content or len(content) < 100:
                return None
            
            # Truncate if too long
            if len(content) > 8000:
                content = content[:8000]
            
            # Generate trajectory with Groq
            user_prompt = f"""Convert this hacking walkthrough into a ReAct-style trajectory:

{content}

Generate a conversational training trajectory following the format above. Include as many turns as needed to complete the walkthrough.
"""
            
            chat_completion = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                temperature=0.7,
                max_tokens=4000,
                response_format={"type": "json_object"}
            )
            
            response = chat_completion.choices[0].message.content
            data = json.loads(response)
            
            # Generate ID
            import hashlib
            traj_id = hashlib.md5(
                f"{source}{datetime.utcnow().isoformat()}".encode()
            ).hexdigest()[:12]
            data["id"] = f"hack_{traj_id}"
            
            # Ensure fields
            if "conversations" not in data:
                data["conversations"] = []
            if "metadata" not in data:
                data["metadata"] = {}
            data["metadata"]["source"] = source
            
            return data
            
        except Exception as e:
            logger.warning(f"Failed to process {source}: {e}")
            return None
    
    # Process sources
    all_sources = []
    if urls:
        all_sources.extend(urls)
    if files:
        all_sources.extend(files)
    
    for i, source in enumerate(all_sources):
        logger.info(f"Processing {i+1}/{len(all_sources)}: {source}")
        
        result = process_source(source)
        
        if result:
            trajectories.append(result)
            logger.info(f"Generated: {result.get('id', 'unknown')}")
        else:
            logger.warning(f"Skipping {source} - processing failed")
        
        processed += 1
    
    # Save to file
    if trajectories and output_file:
        with open(output_file, 'w') as f:
            for traj in trajectories:
                f.write(json.dumps(traj, ensure_ascii=False) + '\n')
        logger.info(f"Saved to {output_file}")
    
    return trajectories


def upload_to_huggingface(
    hf_token: str,
    repo_id: str,
    trajectories: list[dict]
) -> dict:
    """Upload to HuggingFace."""
    try:
        from huggingface_hub import HfApi
        from datasets import Dataset
        
        api = HfApi(token=hf_token)
        
        ds = Dataset.from_list(trajectories)
        
        ds.push_to_hub(
            repo_id=repo_id,
            token=hf_token,
            repo_type="dataset",
            commit_message=f"Add {len(trajectories)} trajectories"
        )
        
        return {
            "success": True,
            "url": f"https://huggingface.co/{repo_id}"
        }
        
    except Exception as e:
        logger.error(f"Upload failed: {e}")
        return {
            "success": False,
            "error": str(e)
        }


# =============================================================================
# FASTAPI APP
# =============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting CyberAgent API")
    yield
    logger.info("Shutting down")


app = FastAPI(
    title="CyberAgent Dataset Generator API",
    version="1.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
async def root():
    """Serve the frontend."""
    return FileResponse("/workspace/project/frontend/index.html")


@app.get("/frontend/{path}")
async def serve_frontend(path: str):
    """Serve frontend assets."""
    return FileResponse(f"/workspace/project/frontend/{path}")


@app.post("/api/generate")
async def generate(request: GenerateRequest):
    """Generate trajectories."""
    try:
        if not request.groq_key:
            raise HTTPException(status_code=400, detail="Groq API key required")
        
        trajectories = generate_trajectories(
            groq_key=request.groq_key,
            urls=request.urls,
            files=request.files,
            output_file=request.output_file
        )
        
        return {
            "success": True,
            "trajectories": trajectories,
            "count": len(trajectories)
        }
        
    except Exception as e:
        logger.error(f"Generation error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/upload-hf")
async def upload_hf(request: UploadRequest):
    """Upload to HuggingFace."""
    try:
        if not request.hf_token or not request.repo_id:
            raise HTTPException(status_code=400, detail="Token and repo ID required")
        
        result = upload_to_huggingface(
            hf_token=request.hf_token,
            repo_id=request.repo_id,
            trajectories=request.trajectories
        )
        
        if not result.get("success"):
            raise HTTPException(status_code=500, detail=result.get("error", "Upload failed"))
        
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Upload error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/health")
async def health():
    return {"status": "healthy"}


# =============================================================================
# ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)