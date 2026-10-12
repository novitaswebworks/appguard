"""Drive an isolated macOS bundle through Accessibility, without mocked IPC.

Only the test process PID is addressed. The normal installed AppGuard and its
configuration are never used. Pass a scratch directory and the validation app.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import time

root = Path(sys.argv[2]).resolve()
state_path = root / "native-process.json"

def apple(script):
    result = subprocess.run(["osascript", "-"], input=script, text=True, capture_output=True, timeout=30)
    if result.returncode:
        raise RuntimeError(result.stderr.strip())
    return result.stdout.strip()

if sys.argv[1] == "launch":
    bundle = Path(sys.argv[3]).resolve()
    import plistlib
    info = plistlib.loads((bundle / "Contents/Info.plist").read_bytes())
    if info["CFBundleIdentifier"] != "com.appguard.beta.validation":
        raise RuntimeError("Use the separately identified validation bundle")
    root.mkdir(parents=True, exist_ok=True)
    config = root / "config"
    config.mkdir(exist_ok=True)
    executable = bundle / "Contents/MacOS" / info["CFBundleExecutable"]
    log = (root / "native.log").open("a")
    process = subprocess.Popen([str(executable)], env={**os.environ, "XDG_CONFIG_HOME": str(config)}, stdout=log, stderr=log, start_new_session=True)
    state_path.write_text(json.dumps({"pid": process.pid, "executable": str(executable)}))
    time.sleep(4)
    if process.poll() is not None:
        raise RuntimeError(f"Validation application exited with {process.returncode}; inspect native.log")
    print(f"Started validation application PID {process.pid}")
else:
    state = json.loads(state_path.read_text())
    pid = state["pid"]
    # Guard against PID reuse; never operate on the user's installed app.
    command = subprocess.check_output(["ps", "-p", str(pid), "-o", "command="], text=True).strip()
    if command != state["executable"]:
        raise RuntimeError("Recorded PID is no longer the validation application")
    prefix = f'tell application "System Events"\nset p to first application process whose unix id is {pid}\ntell p\nset frontmost to true\n'
    suffix = '\nend tell\nend tell'
    mode = sys.argv[1]
    if mode == "snapshot":
        script = '''set output to ""
repeat with w in windows
set output to output & "WINDOW: " & name of w & linefeed
repeat with e in entire contents of w
try
set r to role of e
if r is in {"AXButton", "AXTextField", "AXSecureTextField", "AXStaticText", "AXCheckBox", "AXPopUpButton"} then
set n to ""
set v to ""
try
set n to name of e as text
end try
try
set v to value of e as text
end try
set output to output & r & " | " & n & " | " & v & linefeed
end if
end try
end repeat
end repeat
return output'''
    elif mode == "click":
        label = json.dumps(sys.argv[3])
        script = f'''repeat with w in windows
repeat with e in entire contents of w
try
if role of e is "AXButton" and name of e is {label} then
perform action "AXPress" of e
return "clicked " & {label}
end if
end try
end repeat
end repeat
error "Button not found"'''
    elif mode == "fill":
        index, value = int(sys.argv[3]), json.dumps(sys.argv[4])
        script = f'''set fields to {{}}
repeat with e in entire contents of window 1
if role of e is in {{"AXTextField", "AXSecureTextField"}} then set end of fields to contents of e
end repeat
set e to item {index} of fields
set focused of e to true
keystroke "a" using command down
keystroke {value}
return "filled field {index}"'''
    elif mode == "close":
        script = 'click (first button of window 1 whose subrole is "AXCloseButton")\nreturn "window close requested"'
    else:
        raise RuntimeError("Unknown action")
    print(apple(prefix + script + suffix))
