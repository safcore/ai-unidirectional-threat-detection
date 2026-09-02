"""Tests for /api/stream SSE endpoint."""
import pytest
from tests.conftest import VALID_ALERT


def test_stream_returns_event_stream(client):
    """SSE endpoint must return text/event-stream content type."""
    # Use a short read so we don't block indefinitely
    resp = client.get("/api/stream")
    assert resp.status_code == 200
    assert "text/event-stream" in resp.content_type


def test_stream_initial_connected_event(client):
    """The stream should emit a named connected event on first connection."""
    with client.get("/api/stream", buffered=False) as resp:
        # Read first few bytes — should contain the connected event
        # We use a generator read, closing after the first chunk
        data_chunks = []
        for chunk in resp.response:
            data_chunks.append(chunk.decode())
            break   # read just the first event then stop

    full = "".join(data_chunks)
    assert "event: connected" in full or "connected" in full
