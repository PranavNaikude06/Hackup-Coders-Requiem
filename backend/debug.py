import traceback

try:
    from app.services.attachment_analyzer import AttachmentAnalyzer
    print("SUCCESS")
except SyntaxError as e:
    print(f"SYNTAX_ERROR_FILE: {e.filename}")
    print(f"SYNTAX_ERROR_LINE: {e.lineno}")
    print(f"SYNTAX_ERROR_TEXT: {e.text}")
    print(f"SYNTAX_ERROR_MSG: {e.msg}")
except Exception as e:
    traceback.print_exc()
