import asyncio
import io
import json
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.main import app
from app.services.attachment_analyzer import AttachmentAnalyzer

# Create a sync test client for fastapi endpoints
# For testing StreamingResponses, TestClient behaves closely enough for basic unit test checks
client = TestClient(app)

class TestSSEStreaming(unittest.TestCase):
    @patch('app.api.routes.AttachmentAnalyzer', autospec=True)
    def test_sse_streaming_endpoint(self, mock_analyzer_class):
        # Create an async generator mock to simulate `analyze_stream`
        async def mock_stream(*args, **kwargs):
            yield {"step": "init", "status": "started"}
            yield {"step": "static_analysis", "status": "complete"}
            yield {"step": "complete", "result": {"verdict": "SAFE"}}

        # Wire the mock into the class instance
        instance = mock_analyzer_class.return_value
        instance.analyze_stream.side_effect = mock_stream
        
        # We need a small file to POST
        file_content = b"dummy content"
        f = io.BytesIO(file_content)
        f.name = "test.txt"

        response = client.post("/analyze/attachment/stream", files={"file": ("test.txt", f)})
        
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["content-type"], "text/event-stream; charset=utf-8")
        
        # Streaming response body is collected via TestClient directly into a string
        body = response.text
        
        chunks = body.strip().split("\n\n")
        self.assertEqual(len(chunks), 3, "Expected 3 SSE chunks generated")
        
        # Verify JSON
        first_event = json.loads(chunks[0].replace("data: ", ""))
        self.assertEqual(first_event["step"], "init")
        
        last_event = json.loads(chunks[-1].replace("data: ", ""))
        self.assertEqual(last_event["step"], "complete")
        self.assertEqual(last_event["result"]["verdict"], "SAFE")

if __name__ == "__main__":
    unittest.main()
