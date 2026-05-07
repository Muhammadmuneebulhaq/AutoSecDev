# AutoSecDev (Multi-Agent DevSecOps Security Pipeline)

This repository implements the PRD-defined pipeline:

`SAST Agent (Bandit+Semgrep+LLM reasoning) → Patch Agent (RAG + patching + self-verification) → Report Agent (Markdown)`

It also includes Kaggle-ready `.ipynb` notebooks to fine-tune:
1. **CodeBERT** (vulnerability detection baseline)
2. **CodeT5** (patch generation baseline)

## Quick start (local demo)

### 1) Install Python deps
```powershell
cd "d:\Sem8\GenAI\Project"
pip install -r requirements.txt
```

### 2) Install SAST CLI tools
```powershell
pip install bandit semgrep
```

### 3) Run Streamlit
```powershell
streamlit run streamlit_app.py
```

## GitHub webhook + PR comment

### 1) Set environment variable
Create a token with permissions to read PR contents and post comments.
```powershell
$env:GITHUB_TOKEN="..."
```

### 2) Run FastAPI server
```powershell
uvicorn autosecdev.api.server:app --reload --port 8000
```

### 3) Configure your GitHub webhook
Point GitHub to:
`POST http://<host>:8000/webhook/github`

## LLM provider configuration (optional)
By default, the LLM client uses **Ollama**:
- `AUTOSECDEV_LLM_PROVIDER=ollama`
- `OLLAMA_URL=http://localhost:11434`
- `OLLAMA_MODEL=codellama:7b`

If you don't have an LLM running, the pipeline will still run, but confirmations/patches may be empty.

## Fine-tuning notebooks (Kaggle)
Training code is in `notebooks/` and is intended to be run on Kaggle.
See:
- `notebooks/01_prepare_codebert_dataset_cvefixes.ipynb`
- `notebooks/02_finetune_codebert_lora_cvefixes.ipynb`
- `notebooks/03_prepare_codedt5_patch_dataset_cvefixes.ipynb`
- `notebooks/04_finetune_codedt5_lora_cvefixes.ipynb`

