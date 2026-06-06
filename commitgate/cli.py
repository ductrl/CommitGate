import typer
from rich import print

app = typer.Typer()

@app.command()
def scan():
    print("CommitGate scanned!")

@app.command()
def version():
    print("CommitGate 0.1.0")

if __name__ == "__main__":
    app()