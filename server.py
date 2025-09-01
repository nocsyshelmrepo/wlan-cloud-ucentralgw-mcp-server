
from mcp.server.fastmcp import FastMCP
from mcp.server.sse import SseServerTransport
from starlette.applications import Starlette
from starlette.routing import Route, Mount

from fastapi import HTTPException

import requests

import json
import argparse
from dataclasses import dataclass
from typing import Optional, Dict, Any
import logging, logging

# Initialize FastMCP server
mcp = FastMCP("Ucentral OWGW MCP Server", log_level="ERROR",
              dependencies=[],
              debug=True,
              host='0.0.0.0',
              port=5050)

@mcp.tool()
def update_owgw_addr(addr: str, user: str, password: str):
    """Update OWGW address.
       Args:
           addr: New OWGW address
           user: OWSEC username
           password: OWSEC password
    """
    old_addr = config.owsec_addr
    old_user = config.owsec_user
    old_password = config.owsec_password

    addr = addr.replace("http://", "")
    config.owsec_addr = addr
    config.owsec_user = user
    config.owsec_password = password
    owgw_addr = getowgw_addr(loginowsec())

    if owgw_addr == "":
        config.owsec_addr = old_addr
        config.owsec_user = old_user
        config.owsec_password = old_password
        raise Exception("Failed to discover OWGW address from OWSEC")


@mcp.tool()
def get_systemInfo() -> str:
    """Get OWGW system information."""
    token = loginowsec()
    owgw_addr = getowgw_addr(token)
    try:
        response = requests.get(f"{owgw_addr}/api/v1/system?command=info",
                                headers={"Content-Type": "application/json", "Accept": "application/json", "Authorization": f"Bearer {token}"},
                                timeout=5, verify=False)
        response.raise_for_status()
        return response.text
    except requests.RequestException as e:
        raise HTTPException(status_code=response.status_code, detail=str(e))

@mcp.tool()
def get_systemResource() -> str:
    """Get OWGW system resource usage."""
    token = loginowsec()
    owgw_addr = getowgw_addr(token)
    try:
        response = requests.get(f"{owgw_addr}/api/v1/system?command=resources",
                                headers={"Content-Type": "application/json", "Accept": "application/json", "Authorization": f"Bearer {token}"},
                                timeout=5, verify=False)
        response.raise_for_status()
        return response.text
    except requests.RequestException as e:
        raise HTTPException(status_code=response.status_code, detail=str(e))


@mcp.tool()
def get_device(serail: str) -> str:
    """Get OWGW device information by serial number.
       Agrs:
           serail: Device serial number
    """
    token = loginowsec()
    owgw_addr = getowgw_addr(token)
    try:
        response = requests.get(f"{owgw_addr}/api/v1/device/{serail}",
                                headers={"Content-Type": "application/json", "Accept": "application/json", "Authorization": f"Bearer {token}"},
                                timeout=5, verify=False)
        response.raise_for_status()
        return response.text
    except requests.RequestException as e:
        raise HTTPException(status_code=response.status_code, detail=str(e))

@mcp.tool()
def delete_device(serail: str) -> str:
    """Get OWGW device information by serial number.
        Agrs:
           serail: Device serial number
    """
    token = loginowsec()
    owgw_addr = getowgw_addr(token)
    try:
        response = requests.delete(f"{owgw_addr}/api/v1/device/{serail}",
                                headers={"Content-Type": "application/json", "Accept": "application/json", "Authorization": f"Bearer {token}"},
                                timeout=5, verify=False)
        response.raise_for_status()
        return response.text
    except requests.RequestException as e:
        raise HTTPException(status_code=response.status_code, detail=str(e))

@mcp.tool()
def get_devicestatus(serail: str) -> str:
    """Get OWGW device status by serial number.        
       Agrs:
           serail: Device serial number
    """
    token = loginowsec()
    owgw_addr = getowgw_addr(token)
    try:
        response = requests.get(f"{owgw_addr}/api/v1/device/{serail}/status",
                                headers={"Content-Type": "application/json", "Accept": "application/json", "Authorization": f"Bearer {token}"},
                                timeout=5, verify=False)
        response.raise_for_status()
        return response.text
    except requests.RequestException as e:
        raise HTTPException(status_code=response.status_code, detail=str(e))

@mcp.tool()
def get_devicestats(serial: str) -> str:
    """Get OWGW device stats by serial number.
        Agrs:
           serail: Device serial number
    """
    token = loginowsec()
    owgw_addr = getowgw_addr(token)
    try:
        response = requests.get(f"{owgw_addr}/api/v1/device/{serail}/statistics",
                                headers={"Content-Type": "application/json", "Accept": "application/json", "Authorization": f"Bearer {token}"},
                                timeout=5, verify=False)
        response.raise_for_status()
        return response.text
    except requests.RequestException as e:
        raise HTTPException(status_code=response.status_code, detail=str(e)) 

@mcp.tool()
def get_healthychecks(serial: str) -> str:
    """Get OWGW device healthy checks by serial number.
        Agrs:
           serail: Device serial number
    """
    token = loginowsec()
    owgw_addr = getowgw_addr(token)
    try:
        response = requests.get(f"{owgw_addr}/api/v1/device/{serail}/healthchecks",
                                headers={"Content-Type": "application/json", "Accept": "application/json", "Authorization": f"Bearer {token}"},
                                timeout=5, verify=False)
        response.raise_for_status()
        return response.text
    except requests.RequestException as e:
        raise HTTPException(status_code=response.status_code, detail=str(e))     


@mcp.tool()
def reboot_device(serial: str) -> str:
    """Reboot OWGW device by serial number.
        Agrs:
           serail: Device serial number
    """
    token = loginowsec()
    owgw_addr = getowgw_addr(token)
    try:
        response = requests.get(f"{owgw_addr}/api/v1/device/{serail}/reboot",
                                json={"serialNumber": f"{serial}"},
                                headers={"Content-Type": "application/json", "Accept": "application/json", "Authorization": f"Bearer {token}"},
                                timeout=5, verify=False)
        response.raise_for_status()
        return response.text
    except requests.RequestException as e:
        raise HTTPException(status_code=response.status_code, detail=str(e))     

@mcp.tool()
def get_capabilities(serial: str) -> str:
    """Get OWGW capabilities.
        Agrs:
           serail: Device serial number
    """    
    token = loginowsec()
    owgw_addr = getowgw_addr(token)
    try:
        response = requests.get(f"{owgw_addr}/api/v1/device/{serial}/capabilities",
                                headers={"Content-Type": "application/json", "Accept": "application/json", "Authorization": f"Bearer {token}"},
                                timeout=5, verify=False)
        response.raise_for_status()
        return response.text
    except requests.RequestException as e:
        raise HTTPException(status_code=response.status_code, detail=str(e))

@mcp.tool()
def list_devices() -> str:
    """List OWGW devices."""
    token = loginowsec()
    owgw_addr = getowgw_addr(token) 
    try:
        response = requests.get(f"{owgw_addr}/api/v1/devices",
                                headers={"Content-Type": "application/json", "Accept": "application/json", "Authorization": f"Bearer {token}"},
                                timeout=5, verify=False)
        response.raise_for_status()
        return response.text
    except requests.RequestException as e:
        raise HTTPException(status_code=response.status_code, detail=str(e))

@mcp.tool()
def get_logs(serial: str) -> str:
    """Get OWGW device logs by serial number.
        Agrs:
           serail: Device serial number
    """
    token = loginowsec()
    owgw_addr = getowgw_addr(token)
    try:
        response = requests.get(f"{owgw_addr}/api/v1/device/{serail}/logs",
                                headers={"Content-Type": "application/json", "Accept": "application/json", "Authorization": f"Bearer {token}"},
                                timeout=5, verify=False)
        response.raise_for_status()
        return response.text
    except requests.RequestException as e:
        raise HTTPException(status_code=response.status_code, detail=str(e))


@mcp.tool()
def get_devicecount() -> str:
    """Get OWGW device count."""
    token = loginowsec()
    owgw_addr = getowgw_addr(token)
    try:
        response = requests.get(f"{owgw_addr}/api/v1/devices?countOnly=true",
                                headers={"Content-Type": "application/json", "Accept": "application/json", "Authorization": f"Bearer {token}"},
                                timeout=5, verify=False)
        response.raise_for_status()
        return response.text
    except requests.RequestException as e:
        raise HTTPException(status_code=response.status_code, detail=str(e))

def getowgw_addr(token: str) -> str:
    """Get the OWGW address from restapi.
        Agrs:
           token: token get from loginowsec()
    """

    owgw_addr=""
    if config.owgw_addr == "":
        try:
            response = requests.get(f"https://{config.owsec_addr}/api/v1/systemEndpoints",
                                    headers={"Content-Type": "application/json", "Accept": "application/json",
                                             "Authorization": f"Bearer {token}"},
                                    timeout=5, verify=False)
            response.raise_for_status()
            data = response.json()

            for elem in data['endpoints']:
                if elem['type'] == "owgw":
                    owgw_addr = elem['uri']
                    logging.debug(f"Discovered OWGW address: {owgw_addr}")
                    break

        except requests.RequestException as e:
            raise HTTPException(status_code=response.status_code, detail=str(e))

    return owgw_addr


def loginowsec() -> str:
    """Login to OWSEC and return the authentication token."""

    try:
        response = requests.post(f"https://{config.owsec_addr}/api/v1/oauth2",
                                 json={"userId": config.owsec_user, "password": config.owsec_password},
                                 headers={"Content-Type": "application/json", "Accept": "application/json"},
                                 timeout=5, verify=False)
        response.raise_for_status()
        data = response.json()

        if 'access_token' in data:
            return data['access_token']
        else:
            raise HTTPException(status_code=response.status_code, detail="Token not found in login response")
    except requests.RequestException as e:
        raise HTTPException(status_code=response.status_code, detail=str(e))

# Configuration data class for storing configuration options
@dataclass
class Config:
    owsec_addr: str
    owsec_user: str
    owsec_password: str
    owgw_addr: str
    log_file: Optional[str] = None     # Log file path (if not specified, output to console)
    log_level: str = "INFO"            # Log level


# Parse command-line arguments and environment variables, and load configuration
parser = argparse.ArgumentParser(description="MCP OWGW Management Server")
parser.add_argument("--config", "-c", help="Configuration file path (JSON or YAML)", default=None)
args = parser.parse_args()

config_data = {}
config_path = args.config 
if config_path:
    # Parse JSON or YAML based on the file extension
    if config_path.endswith((".yml", ".yaml")):
        import yaml
        with open(config_path, 'r') as f:
            config_data = yaml.safe_load(f)
    elif config_path.endswith(".json"):
        with open(config_path, 'r') as f:
            config_data = json.load(f)
    else:
        raise ValueError("Unsupported configuration file format. Please use JSON or YAML")
        


# Construct Config object from config_data
required_keys = ["owsec_addr", "owsec_user", "owsec_password"]
for k in required_keys:
    if k not in config_data or not config_data[k]:
        raise Exception(f"Missing required configuration item: {k}")

config = Config(**config_data)

# Initialize logging
log_level = getattr(logging, config.log_level.upper(), logging.INFO)
logging.getLogger().setLevel(log_level)
# add file handler if log_file is specified, we doesn't clear console handler
if config.log_file:
    handler = logging.handlers.RotatingFileHandler(config.log_file, maxBytes=1024000, backupCount=2)
    handler.setFormatter(logging.Formatter(fmt = '%(asctime)s.%(msecs)03d %(levelname)-5s [%(filename)s %(lineno)d %(funcName)s] %(message)s', 
                                           datefmt='%y-%m-%d %H:%M:%S'))
    logging.getLogger().addHandler(handler)

logging.info("Starting OWGW Management MCP Server...")

requests.packages.urllib3.disable_warnings()
owgw_addr = getowgw_addr(loginowsec())
if owgw_addr == "":
    raise Exception("Failed to discover OWGW address from OWSEC")

if __name__ == "__main__":
    mcp.run(transport="sse") # Use "stdio" for testing and mcpo, "sse" for server-sent events
