# wlan-cloud-ucentralgw-mcp-server
1. modify the file, config.yaml
2. create enter virtual environment
```
python3.13 -m venv .venv  
source .venv/bin/activate  
```

3.1. install dependency
```
pip install -r requirement
```
3.2. direcly start mcp server
```
python3.13 server.py  --config config.yaml
```

4. Directly run
```
python3.13 server.py  --config config.yaml
```

5. Run by mcpo (openwebui)
```
mcpo --port 8000 -- python3.13 server.py --config config.yaml
```

6. Using inspector
```
DEBUG=true ALLOWED_ORIGINS=http://192.168.40.131:6274 HOST=192.168.40.131 npx @modelcontextprotocol/inspector
```