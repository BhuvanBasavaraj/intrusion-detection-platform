from fastapi import FastAPI

app = FastAPI(title="Intrusion Detection Platform")


@app.get("/")
def root():
    return {
        "message": "Intrusion Detection Platform API is running"
    }