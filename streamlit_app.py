from __future__ import annotations

import streamlit as st

from autosecdev.agents.patch_agent import PatchAgent
from autosecdev.agents.report_agent import ReportAgent
from autosecdev.agents.sast_agent import SASTAgent
from autosecdev.settings import settings


st.set_page_config(page_title="AutoSecDev Demo", layout="wide")
st.title("AutoSecDev - Multi-Agent DevSecOps Security Pipeline (Demo)")

st.markdown(
    """
This demo runs the pipeline locally:
1) Bandit + Semgrep (tool layer)
2) LLM reasoning to confirm/dismiss findings
3) Patch agent with RAG context and a self-verification loop
"""
)

# Check LLM configuration
st.sidebar.subheader("⚙️ System Status")
from autosecdev.settings import settings
st.sidebar.write(f"**LLM Provider**: {settings.llm_provider}")
if settings.llm_provider == "ollama":
    st.sidebar.write(f"**Ollama URL**: {settings.ollama_url}")
    st.sidebar.write(f"**Ollama Model**: {settings.ollama_model}")
    st.sidebar.info("ℹ️ Make sure Ollama is running: `ollama serve` and has the model pulled: `ollama pull codellama:7b`")
elif settings.llm_provider == "openai":
    st.sidebar.write(f"**OpenAI Model**: {settings.openai_model}")
    if not settings.openai_api_key:
        st.sidebar.error("⚠️ OPENAI_API_KEY not set")
elif settings.llm_provider == "claude":
    st.sidebar.write(f"**Claude Model**: {settings.anthropic_model}")
    if not settings.anthropic_api_key:
        st.sidebar.error("⚠️ ANTHROPIC_API_KEY not set")

default_code = """\
def unsafe_eval(user_input: str):
    return eval(user_input)
"""

code = st.text_area("Paste Python code to scan", value=default_code, height=250)
file_path = st.text_input("Logical file path (for report)", value="example.py")

run = st.button("Run pipeline")

if run:
    with st.spinner("Running SAST + Patch pipeline..."):
        try:
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
            patch_report = patch_agent.patch({file_path: code}, sast_report, max_iterations=settings.max_patch_iterations)
            
            if not patch_report.patched_files:
                st.warning("⚠️ No patches were generated. Check LLM configuration and ensure it's running.")
            else:
                st.success(f"✓ Generated {len(patch_report.patched_files)} patch(es)")

            report_agent = ReportAgent()
            st.info("📋 Step 3: Generating report...")
            report_markdown = report_agent.render_markdown(sast_report, patch_report)
        except Exception as e:
            st.error(f"❌ Pipeline failed: {str(e)}")
            import traceback
            st.code(traceback.format_exc(), language="python")
            raise

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

    st.subheader("Patch diffs")
    if not patch_report.patched_files:
        st.write("No patch diffs produced.")
    else:
        for pf in patch_report.patched_files:
            st.markdown(f"### {pf.file_path}")
            st.code(pf.unified_diff, language="diff")

