import logging
import os
import sys

from fastapi import FastAPI, File, Header, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from loguru import logger

from backend.db import Neo4j
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


def get_neo4j_server():
    return (
        "bolt://beacongraph-neo4j:7687"
        if os.environ.get("DOCKER_BEACONGRAPH")
        else "bolt://localhost:7687"
    )


@app.post("/api/upload")
async def process_upload(
    x_neo4j_user: str = Header("neo4j"),
    x_neo4j_pass: str = Header("password"),
    upload: UploadFile = File(...),
):
    contents = await upload.read()
    try:
        await airohandler.process(
            contents, upload.filename, x_neo4j_user, x_neo4j_pass,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Upload processing failed")
        raise HTTPException(
            status_code=500,
            detail=f"{exc.__class__.__name__}: {exc}",
        ) from exc

    return {"status": "Upload Success"}


@app.delete("/api/data")
async def clear_data(
    x_neo4j_user: str = Header("neo4j"),
    x_neo4j_pass: str = Header("password"),
):
    client = None
    try:
        client = Neo4j(
            server=get_neo4j_server(),
            user=x_neo4j_user,
            password=x_neo4j_pass,
        )
        client.deleteDB()
    except Exception as exc:
        logger.exception("Database clear failed")
        raise HTTPException(
            status_code=500,
            detail=f"{exc.__class__.__name__}: {exc}",
        ) from exc
    finally:
        if client is not None:
            client.shutdown()

    return {"status": "Database cleared"}
