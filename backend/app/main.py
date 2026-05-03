import asyncio
import contextlib
import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import models
from app.db import engine
from app.routes import router, run_due_scheduled_scans_job


SCHEDULER_CHECK_INTERVAL_SECONDS = int(
    os.getenv("DNSCOPE_SCHEDULER_CHECK_SECONDS", "60")
)


app = FastAPI(title="DNScope")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# create database tables on startup
# this keeps development simple while the data model is still changing
models.Base.metadata.create_all(bind=engine)


async def scheduled_scan_loop():
    # periodically check for domains that have scheduled scans enabled and are due
    while True:
        await asyncio.sleep(SCHEDULER_CHECK_INTERVAL_SECONDS)

        try:
            await asyncio.to_thread(run_due_scheduled_scans_job)
        except Exception as error:
            print(f"scheduled scan job failed: {error}")


@app.on_event("startup")
async def start_scheduler():
    # start one background scheduler task for this api process
    app.state.scheduler_task = asyncio.create_task(scheduled_scan_loop())


@app.on_event("shutdown")
async def stop_scheduler():
    # stop the background scheduler task when the api process shuts down
    scheduler_task = getattr(app.state, "scheduler_task", None)

    if scheduler_task:
        scheduler_task.cancel()

        with contextlib.suppress(asyncio.CancelledError):
            await scheduler_task


app.include_router(router)


@app.get("/health")
def health():
    return {"status": "ok"}
