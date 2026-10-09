import os
import sys
from openai import OpenAI
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.markdown import Markdown

load_dotenv()
console = Console()

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

def analyze_logs(log_file_path):
    try:
        with open(log_file_path, 'r', encoding='utf-8') as f:
            logs = f.read()
    except Exception as e:
        console.print(f"[red]Error reading logs: {e}[/red]")
        return

    console.print(Panel(f"[cyan]Analyzing security logs from {log_file_path}...[/cyan]", title="[bold]Attack Intelligence Engine[/bold]"))

    prompt = f"""
    You are an expert Incident Responder and Defensive Security AI. Analyze the following log events. Group and correlate any suspicious or malicious activity.
    
    Structure your report as follows:
    - **Executive Summary**: What happened and the overall threat level.
    - **Reconstructed Attack Path**: Step-by-step chronology of the attacker's actions.
    - **MITRE ATT&CK Mapping**: Map the behaviors to specific MITRE tactics/techniques (e.g., Reconnaissance, Credential Access).
    - **Recommended Defenses & Hardening Rules**: Specific recommendations (e.g. firewall/WAF rule, rate limiting, configuration changes) to stop this attack permanently.

    Logs:
    {logs}
    """

    try:
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": "You are an expert Attack Intelligence Agent that turns fragmented telemetry signals into clear security incident reports."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.2
        )

        analysis = response.choices[0].message.content
        console.print(Panel("Incident Investigation Report", style="bold red"))
        console.print(Markdown(analysis))

    except Exception as e:
        console.print(f"[red]AI Log Analysis failed: {e}[/red]")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python sentinel/log_analyzer.py <path_to_log_file>")
        sys.exit(1)
    
    analyze_logs(sys.argv[1])
