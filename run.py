import uvicorn

if __name__ == "__main__":
    print("\n========================================================")
    print("  MirageNet - AI-Powered Cyber Deception Platform")
    print("  Open in browser: http://127.0.0.1:8000")
    print("========================================================\n")
    uvicorn.run("backend.main:app", host="127.0.0.1", port=8000, reload=True)
