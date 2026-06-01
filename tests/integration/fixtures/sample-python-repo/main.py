"""Fixture file with one rule-triggering pattern for the scanner-http integration test.

``eval`` over user-supplied input is flagged by semgrep-rules'
``python.lang.security.audit.eval-detected.eval-detected`` rule, which is bundled
into the code-scanning container at ``/scanner/rules``.
"""

def run() -> None:
    print(eval(input("expr: ")))


if __name__ == "__main__":
    run()
