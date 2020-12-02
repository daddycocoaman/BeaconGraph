import logging
import sys

from fastapi import BackgroundTasks, FastAPI, File, Header, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from loguru import logger

from backend.logs import InterceptHandler, format_record, logger
from backend.parser import AirodumpProcessor

# LOGGING
logger.configure(
    handlers=[
        {
            "sink": sys.stdout,
            "level": logging.DEBUG,
            "format": format_record,
            "backtrace": True,
        },
    ],
)
logging.getLogger("uvicorn.access").handlers = [InterceptHandler()]

app = FastAPI(
    title="Beacongraph-Backend",
    description="API Handler for beacongraph",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

airohandler = AirodumpProcessor()


@app.post("/api/upload")
async def process_upload(
    task: BackgroundTasks,
    x_neo4j_user: str = Header("neo4j"),
    x_neo4j_pass: str = Header("password"),
    upload: UploadFile = File(...),
):
    contents = await upload.read()
    task.add_task(
        airohandler.process, contents, upload.filename, x_neo4j_user, x_neo4j_pass,
    )
    return {"status": "Upload Success"}
