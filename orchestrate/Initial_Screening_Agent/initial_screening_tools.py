# sample_tool.py
import subprocess
import os
from ibm_watsonx_orchestrate.agent_builder.tools import tool, ToolPermission


@tool(name="initial_screening", description="Runs Nikto to determine any initial security vulnerabilities with the given website.", permission=ToolPermission.ADMIN)
def run_nikto_direct(website_link: str) -> str:
    base_dir = os.path.dirname(os.path.abspath(__file__))
    file_path = os.path.join(base_dir, "nikto/program/nikto.pl")
    cmd = [
        "perl", file_path, "-h", website_link
    ]
    output = subprocess.run(cmd, capture_output=True, text=True)
    return output.stdout

# print(run_nikto_direct("https://www.transformatech.com"))