#!/bin/sh
set -eu

printf '%s\n' '[FAKE POPUP] Warning: simulated virus detected.'
printf '%s\n' '[FAKE POPUP] No real desktop window or system change is performed.'

python3 -c 'source = "from pathlib import Path\nPath(\"/workspace/output/fake_popup_marker.txt\").write_text(\"simulation complete\\n\", encoding=\"utf-8\")"; exec(compile(source, "<dynamic-test>", "exec"))'

python3 -c 'import socket; socket.create_connection(("203.0.113.1", 9), timeout=1)' 2>/dev/null || printf '%s\n' '[FAKE POPUP] Network attempt blocked as expected.'

printf '%s\n' '[FAKE POPUP] Simulation complete.'
