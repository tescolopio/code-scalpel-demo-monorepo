import subprocess


def run_tool(arg: str) -> None:
    subprocess.run(["echo", arg], check=True)
