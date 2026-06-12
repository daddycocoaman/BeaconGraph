import os

import uvicorn


def main():
    host = os.getenv("BEACONGRAPH_HOST", "0.0.0.0")
    port = int(os.getenv("BEACONGRAPH_PORT", "9090"))
    reload = os.getenv("BEACONGRAPH_RELOAD", "0") == "1"

    uvicorn.run(
        "backend.main:app",
        host=host,
        port=port,
        reload=reload,
    )


if __name__ == "__main__":
    main()
