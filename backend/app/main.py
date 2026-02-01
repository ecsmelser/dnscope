from fastapi import FastAPI

app = FastAPI(title="DNScope")

@app.get("/health")
def health():
    return {"status": "ok"}
