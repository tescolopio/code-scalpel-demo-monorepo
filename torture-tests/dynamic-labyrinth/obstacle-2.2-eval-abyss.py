"""
Use of eval/exec on tainted data, including obfuscation and nesting.
Expected: Code Scalpel must flag every entry point as critical and
acknowledge that executed code is unanalyzable.
"""
import base64


def execute_raw(user_input: str):
    # Direct evaluation of attacker input.
    return eval(user_input)


def execute_computed(operation: str, x: int):
    # Partially constructed string still dynamic at runtime.
    return eval(f"compute_{operation}({x})")


def execute_obfuscated(payload: str):
    # Obfuscation hides the executed code.
    code = base64.b64decode(payload).decode("utf-8")
    exec(code, {})


def nested_eval(expr: str):
    # eval-of-eval turns single input into multiple executions.
    return eval("eval(expr)", {"expr": expr})


def comprehension_eval(values: list[str]):
    # Dynamic evaluation inside a comprehension.
    return [eval(v) for v in values]
