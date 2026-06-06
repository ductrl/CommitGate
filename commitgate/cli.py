import typer
from rich import print

app = typer.Typer()

@app.command()
def scan():
    # TODO: Implement
    print("[green]CommitGate scanned![/green]")

@app.command()
def install_hook():
    # TODO: Implement
    print("Installing Git hook...")

@app.command()
def version():
    print("CommitGate 0.1.0")

if __name__ == "__main__":
    app()