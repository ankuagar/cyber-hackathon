import os
import sys
import argparse
from openai import OpenAI
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.markdown import Markdown

load_dotenv()
console = Console()

# Initialize OpenAI client (Ensure OPENAI_API_KEY is set in your environment)
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

def read_file(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return f.read()
    except Exception as e:
        console.print(f"[red]Error reading {file_path}: {e}[/red]")
        return None

def write_file(file_path, content):
    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content)
        return True
    except Exception as e:
        console.print(f"[red]Error writing to {file_path}: {e}[/red]")
        return False

def discover_threats_and_remediate(file_path, auto_apply=False):
    code_content = read_file(file_path)
    if not code_content:
        return

    console.print(Panel(f"[yellow]Scanning {file_path} for vulnerabilities and misconfigurations...[/yellow]", title="[bold]Threat Discovery[/bold]"))

    prompt = f"""
    You are a Defensive AI Security Engineer. Analyze the following source code/configuration file for security vulnerabilities, OWASP Top 10 issues, misconfigurations, or hardcoded secrets.

    Provide your response in two distinct parts:
    1. A detailed security analysis in Markdown format outlining discovered threats, their severity, and attack paths.
    2. A remediated, safe, and fully patched version of the file. Surround the patched code with a custom codeblock starting with ````SAFE_CODE_START```` and ending with ````SAFE_CODE_END````. Ensure the safe code preserves all functionality but fixes the vulnerability robustly.

    File Content to Scan:
    ```
    {code_content}
    ```
    """

    try:
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": "You are an expert cybersecurity defense AI assistant specializing in static application security testing (SAST) and autonomous patching."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.2
        )

        output = response.choices[0].message.content

        # Separate the markdown report from the safe code
        report = output
        safe_code = ""
        if "SAFE_CODE_START" in output:
            parts = output.split("SAFE_CODE_START")
            report = parts[0]
            code_part = parts[1].split("SAFE_CODE_END")[0]
            # Clean up potential leading/trailing markdown tags from extraction
            safe_code = code_part.strip().strip("`").strip("\n")

        console.print(Panel("Scan Results & Threat Assessment", style="bold green"))
        console.print(Markdown(report))

        if safe_code:
            console.print(Panel("[green]Secure code remediation successfully generated![/green]", title="[bold]Autonomous Remediation[/bold]"))
            if auto_apply:
                # Create backup
                backup_path = f"{file_path}.bak"
                write_file(backup_path, code_content)
                console.print(f"[yellow]Backup of original file saved to: {backup_path}[/yellow]")
                
                # Write remediated code
                if write_file(file_path, safe_code):
                    console.print(f"[bold green]Successfully patched {file_path} autonomously![/bold green]")
            else:
                console.print("\n[yellow]Run with --apply flag to automatically overwrite the file with the remediated secure version.[/yellow]\n")
                console.print("[bold cyan]Remediated Code Suggestion:[/bold cyan]")
                console.print(safe_code)
        else:
            console.print("[green]No serious vulnerabilities requiring immediate automated remediation detected.[/green]")

    except Exception as e:
        console.print(f"[red]AI Threat discovery execution failed: {e}[/red]")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SentinelAI Defensive Security Agent")
    parser.add_argument("--scan", help="Path to a source code or config file to scan")
    parser.add_argument("--apply", action="store_true", help="Automatically apply the secure remediations and backup original")
    args = parser.parse_args()

    if args.scan:
        discover_threats_and_remediate(args.scan, auto_apply=args.apply)
    else:
        parser.print_help()
