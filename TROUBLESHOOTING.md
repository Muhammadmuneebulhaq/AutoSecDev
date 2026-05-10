# Troubleshooting Guide — Local Models

## Error: "Can't load the model for 'Salesforce/codet5-base'"

### Root Cause
The CodeT5 base model cannot be downloaded from Hugging Face Hub. This can happen due to:
- Network connectivity issues
- Firewall/proxy blocking HF Hub
- Disk space issues
- Timeout during download

### Solutions (in order)

#### 1. **Check Internet Connection**
```bash
# Test connectivity to Hugging Face
ping huggingface.co
```

#### 2. **Try Again (Retry)**
The download may have timed out. Just run the app again:
```bash
streamlit run streamlit_app.py
```

#### 3. **Increase Timeout**
Edit `autosecdev/agents/local_patch_agent.py` and change:
```python
timeout=30  # Change to 60 or 120
```

#### 4. **Use Detection-Only Mode**
If CodeT5 won't load, the app will automatically fall back to **detection-only mode**:
- ✓ Vulnerabilities are detected (CodeBERT works)
- ✗ Patches are not generated (CodeT5 failed)
- Shows warning in UI with workaround options

#### 5. **Switch to Classic Mode**
Use the original Bandit/Semgrep + LLM pipeline:
1. In sidebar, select: `🌐 Classic (Bandit/Semgrep + LLM)`
2. Configure LLM provider (Ollama or OpenRouter)
3. Run pipeline

#### 6. **Manual Model Download**
Download CodeT5 manually and cache it:
```bash
python -c "
from transformers import T5ForConditionalGeneration, AutoTokenizer
print('Downloading CodeT5...')
model = T5ForConditionalGeneration.from_pretrained('Salesforce/codet5-base')
tokenizer = AutoTokenizer.from_pretrained('microsoft/codebert-base')
print('Done! Models cached locally.')
"
```

#### 7. **Check Disk Space**
CodeT5 requires ~2GB free space:
```bash
# Windows
dir C:\  # Check free space

# Linux/Mac
df -h
```

#### 8. **Clear Cache and Retry**
```bash
# Remove cached models
rm -rf ~/.cache/huggingface/hub/models--Salesforce--codet5-base
rm -rf ~/.cache/huggingface/hub/models--microsoft--codebert-base

# Try again
streamlit run streamlit_app.py
```

---

## Error: "Input must be a List[Union[str, AddedToken]]"

### Root Cause
Tokenizer configuration is corrupted.

### Solution
Already fixed! The app now uses CodeBERT's tokenizer (compatible with CodeT5).

If you still see this error:
1. Clear cache: `rm -rf ~/.cache/huggingface/hub/`
2. Restart app: `streamlit run streamlit_app.py`

---

## Error: "CUDA out of memory"

### Root Cause
GPU doesn't have enough memory for both models.

### Solutions

#### 1. **Close Other Apps**
Close GPU-intensive applications (games, other ML apps, etc.)

#### 2. **Use CPU Instead**
Models will automatically fall back to CPU (slower but works):
- Detection: ~1-2s per file
- Patching: ~10-30s per patch

#### 3. **Load Models Separately**
Run detection and patching in separate sessions:
```bash
# Session 1: Detection only
streamlit run streamlit_app.py
# Select local models, run detection, close

# Session 2: Patching only
streamlit run streamlit_app.py
# Select local models, run patching
```

#### 4. **Use Quantization** (Advanced)
Reduce model size with int8 quantization:
```python
from transformers import T5ForConditionalGeneration
model = T5ForConditionalGeneration.from_pretrained(
    'Salesforce/codet5-base',
    load_in_8bit=True,
    device_map='auto'
)
```

---

## Error: "Model loaded: False"

### Root Cause
Model files are missing or corrupted.

### Solutions

#### 1. **Check Model Files Exist**
```bash
ls -la Models/DetectionModel/codebert_lora_finetuned/
ls -la Models/PatchingModel/codet5_lora_finetuned/
```

Both should have:
- `adapter_config.json`
- `adapter_model.safetensors`
- `tokenizer.json`
- `tokenizer_config.json`

#### 2. **Check File Permissions**
```bash
# Linux/Mac
chmod 644 Models/*/codet5_lora_finetuned/*
chmod 644 Models/*/codebert_lora_finetuned/*
```

#### 3. **Verify File Integrity**
Check file sizes are reasonable (not 0 bytes):
```bash
ls -lh Models/*/codet5_lora_finetuned/adapter_model.safetensors
ls -lh Models/*/codebert_lora_finetuned/adapter_model.safetensors
```

#### 4. **Re-extract Model Files**
If using zip files:
```bash
unzip -o Models/DetectionModel/model1.zip -d Models/DetectionModel/
unzip -o Models/PatchingModel/model2.zip -d Models/PatchingModel/
```

---

## Error: "No vulnerabilities detected"

### Possible Causes

1. **Code is actually secure** ✓ (Good!)
2. **Heuristic patterns didn't match** — CodeBERT needs patterns to start
3. **Model confidence is low** — Try obvious vulnerabilities first

### Solutions

#### 1. **Test with Known Vulnerable Code**
```python
def unsafe_eval(user_input: str):
    return eval(user_input)
```

#### 2. **Check Model Load Status**
Look at sidebar — should show "Model loaded: True"

#### 3. **Enable Debug Logging**
Check terminal output for model inference logs

#### 4. **Compare with Classic Mode**
Run same code in Classic mode to see if it detects vulnerabilities

---

## Performance Issues

### Detection is Slow

**Cause**: Running on CPU  
**Solution**: Use GPU or reduce code size

### Patching is Slow

**Cause**: CodeT5 generation is slow  
**Solution**:
- Use GPU (10x faster)
- Reduce code snippet size
- Reduce `max_iterations` in settings

### App Takes Forever to Start

**Cause**: First run downloads models  
**Solution**: Wait 5-10 minutes on first run. Subsequent runs are fast.

---

## Network Issues

### Behind Corporate Firewall

**Problem**: Can't download models from Hugging Face  
**Solution**:
1. Configure proxy:
   ```bash
   export HTTP_PROXY=http://proxy.company.com:8080
   export HTTPS_PROXY=http://proxy.company.com:8080
   ```

2. Or download models manually on a machine with internet, then transfer

### Timeout During Download

**Problem**: Download takes too long and times out  
**Solution**:
1. Increase timeout in code (see above)
2. Try again (may be temporary network issue)
3. Download manually on faster connection

---

## Still Having Issues?

### Collect Debug Info

```bash
# 1. Check Python version
python --version

# 2. Check installed packages
pip list | grep -E "torch|transformers|peft"

# 3. Check GPU availability
python -c "import torch; print(torch.cuda.is_available())"

# 4. Check model files
ls -lh Models/*/codet5_lora_finetuned/
ls -lh Models/*/codebert_lora_finetuned/

# 5. Check cache
ls -lh ~/.cache/huggingface/hub/
```

### Report Issue

Include:
- Error message (full traceback)
- Python version
- Installed package versions
- OS (Windows/Linux/Mac)
- GPU info (if applicable)
- Debug info from above

---

## Quick Reference

| Issue | Quick Fix |
|-------|-----------|
| Model won't download | Check internet, try again |
| CUDA out of memory | Close other apps, use CPU |
| Model files missing | Check Models/ directory |
| Tokenizer error | Clear cache, restart |
| No vulnerabilities | Test with obvious vuln code |
| Slow performance | Use GPU, reduce code size |
| App won't start | Wait for model download |

---

## Fallback Options

If local models don't work:

1. **Detection-Only Mode** (automatic fallback)
   - CodeBERT detection works
   - No patching
   - Shows warning in UI

2. **Classic Mode**
   - Bandit + Semgrep detection
   - LLM-based patching
   - Requires LLM provider configured

3. **Manual Approach**
   - Use Bandit/Semgrep CLI directly
   - Use LLM API directly
   - Combine results manually
