from contextlib import asynccontextmanager

from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import routes
from app.api.stream_routes import stream_router
from app.api.apikey_routes import apikey_router
from app.services.email_nlp import EmailNLPService
from app.services.text_analyzer import TextAnalyzer

@asynccontextmanager
async def lifespan(app: FastAPI):
    email_service = EmailNLPService()
    email_service.preload()
    routes.set_email_service(email_service)

    text_service = TextAnalyzer()
    text_service.preload()
    routes.set_text_service(text_service)
    yield


app = FastAPI(title="ThreatLens API", version="2.0", lifespan=lifespan)

# CORS — allow all origins so any frontend can connect
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(routes.router, prefix="/analyze")
app.include_router(stream_router, prefix="/analyze")
app.include_router(apikey_router, prefix="/api/v1/apikey", tags=["API Keys"])


@app.get("/")
def health():
    return {"status": "ok"}
