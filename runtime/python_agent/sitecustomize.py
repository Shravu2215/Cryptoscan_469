"""
Auto-loader for Python CryptoScan Tracer.
Executed automatically when PYTHONPATH includes runtime/python_agent or parent directory.
"""
try:
    import tracer
except ImportError:
    try:
        from runtime.python_agent import tracer
    except Exception:
        pass
