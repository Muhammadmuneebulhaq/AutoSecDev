from __future__ import annotations

import streamlit as st

from autosecdev.agents.patch_agent import PatchAgent
from autosecdev.agents.report_agent import ReportAgent
from autosecdev.agents.sast_agent import SASTAgent
from autosecdev.settings import settings

st.set_page_config(page_title="AutoSecDev Demo", layout="wide")
st.title("AutoSecDev - Multi-Agent DevSecOps Security Pipeline (Demo)")

# ---------------------------------------------------------------------------
# Sidebar — mode toggle + system status
# ---------------------------------------------------------------------------
st.sidebar.header("🔧 Pipeline Mode")

pipeline_mode = st.sidebar.radio(
    "Detection & Patching backend",
    options=["🌐 Classic (Bandit/Semgrep + LLM)", "🤖 Local Fine-tuned Models (CodeBERT + CodeT5)"],
    index=0,
    help=(
        "Classic: uses Bandit + Semgrep for detection and an external LLM for patching.\n\n"
        "Local Models: uses the fine-tuned CodeBERT classifier for detection and the "
        "fine-tuned CodeT5 model for patch generation — no external API required."
    ),
)

use_local_models = pipeline_mode.startswith("🤖")

st.sidebar.divider()
st.sidebar.subheader("⚙️ System Status")

if use_local_models:
    st.sidebar.info("🤖 Using local fine-tuned models")
    st.sidebar.write("**Detection**: CodeBERT + LoRA (`codebert_lora_finetuned`)")
    st.sidebar.write("**Patching**: CodeT5 + LoRA (`codet5_lora_finetuned`)")
    st.sidebar.caption(
        "Models are loaded from `Models/DetectionModel` and `Models/PatchingModel`. "
        "First run may take a moment to load weights."
    )
else:
    st.sidebar.write(f"**LLM Provider**: {settings.llm_provider}")
    if settings.llm_provider == "ollama":
        st.sidebar.write(f"**Ollama URL**: {settings.ollama_url}")
        st.sidebar.write(f"**Ollama Model**: {settings.ollama_model}")
        st.sidebar.info(
            "ℹ️ Make sure Ollama is running: `ollama serve` and has the model pulled: "
            "`ollama pull codellama:7b`"
        )
    elif settings.llm_provider == "openrouter":
        st.sidebar.write(f"**OpenRouter Model**: {settings.openrouter_model}")
        if not settings.openrouter_api_key:
            st.sidebar.error("⚠️ OPENROUTER_API_KEY not set")
        else:
            st.sidebar.info("ℹ️ Using OpenRouter with free models")

# ---------------------------------------------------------------------------
# Description banner
# ---------------------------------------------------------------------------
if use_local_models:
    st.markdown(
        """
This demo runs the pipeline using **locally fine-tuned models**:
1. **CodeBERT + LoRA** — classifies code snippets as vulnerable / clean
2. **CodeT5 + LoRA** — generates patched code from vulnerable blocks
3. Report agent renders the final markdown report
"""
    )
else:
    st.markdown(
        """
This demo runs the pipeline locally:
1. Bandit + Semgrep (tool layer)
2. LLM reasoning to confirm/dismiss findings
3. Patch agent with RAG context and a self-verification loop
"""
    )

# ---------------------------------------------------------------------------
# Code input
# ---------------------------------------------------------------------------
default_code = """\
def unsafe_eval(user_input: str):
    return eval(user_input)
"""

code = st.text_area("Paste Python code to scan", value=default_code, height=250)
file_path = st.text_input("Logical file path (for report)", value="example.py")

run = st.button("▶ Run pipeline")

# ---------------------------------------------------------------------------
# Pipeline execution
# ---------------------------------------------------------------------------
if run:
    with st.spinner("Running pipeline..."):
        try:
            if use_local_models:
                # ── Local model pipeline ──────────────────────────────────
                from autosecdev.agents.local_detection_agent import LocalDetectionAgent
                from autosecdev.agents.local_patch_agent import LocalPatchAgent

                detection_agent = LocalDetectionAgent()

                if not detection_agent.is_loaded:
                    st.error(
                        f"❌ Failed to load CodeBERT detection model: {detection_agent.load_error}\n\n"
                        "Make sure `transformers`, `peft`, and `torch` are installed."
                    )
                    st.stop()

                st.info("🤖 Step 1: Running local CodeBERT classifier...")
                sast_report = detection_agent.scan_files({file_path: code})

                if not sast_report.findings:
                    st.warning("⚠️ No vulnerabilities detected by the local model.")
                else:
                    confirmed = [f for f in sast_report.findings if f.confirmed]
                    st.success(f"✓ CodeBERT found {len(confirmed)} confirmed vulnerability/ies")

                patch_agent = LocalPatchAgent(detection_agent=detection_agent)

                if not patch_agent.is_loaded:
                    st.warning(
                        f"⚠️ CodeT5 patching model failed to load: {patch_agent.load_error}\n\n"
                        "**Workaround**: Using detection-only mode. Vulnerabilities detected but not patched.\n\n"
                        "To fix:\n"
                        "1. Check internet connection (model downloads from Hugging Face)\n"
                        "2. Try again (may be a temporary network issue)\n"
                        "3. Switch to Classic mode (Bandit/Semgrep + LLM)"
                    )
                    # Continue with detection-only results
                    patch_report = PatchReport(
                        patched_files=[],
                        verified=False,
                        iterations_used=0,
                        final_sast=sast_report,
                        unresolved_findings=[f for f in sast_report.findings if f.confirmed],
                    )
                else:
                    st.info("🤖 Step 2: Generating patches with local CodeT5 model...")
                    patch_report = patch_agent.patch(
                        {file_path: code},
                        sast_report,
                        max_iterations=settings.max_patch_iterations,
                    )

            else:
                # ── Classic pipeline ──────────────────────────────────────
                sast_agent = SASTAgent()
                st.info("🔍 Step 1: Running SAST (Bandit + Semgrep)...")
                sast_report = sast_agent.scan_files({file_path: code})

                if not sast_report.findings:
                    st.warning("⚠️ No vulnerabilities detected by SAST tools.")
                else:
                    confirmed = [f for f in sast_report.findings if f.confirmed]
                    st.success(f"✓ SAST found {len(confirmed)} confirmed vulnerability/ies")

                patch_agent = PatchAgent(sast_agent=sast_agent)
                st.info("🧩 Step 2: Generating patches with RAG + LLM...")
                patch_report = patch_agent.patch(
                    {file_path: code},
                    sast_report,
                    max_iterations=settings.max_patch_iterations,
                )

            if not patch_report.patched_files:
                st.warning("⚠️ No patches were generated.")
            else:
                st.success(f"✓ Generated {len(patch_report.patched_files)} patch(es)")

            report_agent = ReportAgent()
            st.info("📋 Step 3: Generating report...")
            report_markdown = report_agent.render_markdown(sast_report, patch_report)

        except Exception as e:
            st.error(f"❌ Pipeline failed: {str(e)}")
            import traceback
            st.code(traceback.format_exc(), language="python")
            st.stop()

    # ── Results ──────────────────────────────────────────────────────────
    st.subheader("Security Report (Markdown)")
    st.code(report_markdown, language="markdown")

    st.subheader("Detected findings (confirmed)")
    confirmed = [f for f in sast_report.findings if f.confirmed]
    if not confirmed:
        st.write("No confirmed findings.")
    else:
        for f in confirmed:
            st.markdown(f"### {f.cwe_id or 'CWE-unknown'} | {f.severity.upper()}")
            st.write(f"File: {f.file_path}, Lines: {f.line_start}-{f.line_end}")
            st.write(f"Description: {f.description}")
            if f.tool_sources:
                st.caption(f"Source: {', '.join(f.tool_sources)}")

    st.subheader("Patch diffs")
    if not patch_report.patched_files:
        st.write("No patch diffs produced.")
    else:
        for pf in patch_report.patched_files:
            st.markdown(f"### {pf.file_path}")
            st.code(pf.unified_diff, language="diff")
            for exp in pf.explanations:
                st.caption(exp.summary)
