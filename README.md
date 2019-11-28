# netsec-sft
CS6349 Network Security Project 19F: secure file transfer

## Setup
Requires Python3.6 or higher
```
python3.6 -m venv sft
source sft/bin/activate
pip install cryptography
```

## Execution
Use viritual environment: `source sft/bin/activate`
Start server first: `python server.py`
Then start client: `python client.py <mode> <file>`
where `mode` is `up` or `down` for upload or download, respectively.
