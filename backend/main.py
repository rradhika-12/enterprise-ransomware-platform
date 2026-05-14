from fastapi import FastAPI

app = FastAPI(
    title="Enterprise Ransomware Early Interception Platform",
    version="1.0.0"
)

@app.get("/")
def root():
    return {
        "message": "Enterprise Ransomware Early Interception Platform Running"
    }