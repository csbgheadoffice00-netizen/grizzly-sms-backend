from fastapi import FastAPI

def hide_docs(app: FastAPI):
    app.openapi_url = None
    app.docs_url = None
    app.redoc_url = None
