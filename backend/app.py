import uvicorn


def main():
    uvicorn.run(
        "backend.main:app", reload=True, host="0.0.0.0", port=9090,
    )


if __name__ == "__main__":
    main()
