import io
import sys
import unittest

def run_tests():
    # Load tests from scripts/test_phase11.py
    sys.path.insert(0, r"d:\hackup")
    import scripts.test_phase11
    
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(scripts.test_phase11)
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    if result.failures:
        for fail in result.failures:
            print("FAILURE:", fail[0])
            print(fail[1])
    if result.errors:
        for err in result.errors:
            print("ERROR:", err[0])
            print(err[1])

if __name__ == "__main__":
    run_tests()
