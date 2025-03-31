# volatility_mcp_server.py
import os
import sys
import subprocess
import json
from pathlib import Path
from typing import List, Dict, Any, Optional
import asyncio

from mcp.server.fastmcp import FastMCP, Context

# Create an MCP server
mcp = FastMCP("VolatilityForensics")

# Configuration
# Using os.path to ensure cross-platform compatibility
VOLATILITY_PYTHON = sys.executable  # Use the current Python interpreter
VOLATILITY_DIR = os.path.normpath(r"C:\Users\visha\Desktop\volatility3")
VOLATILITY_SCRIPT = os.path.join(VOLATILITY_DIR, "vol.py")

# Create a wrapper function for running volatility commands
async def run_volatility(cmd_args, cwd=VOLATILITY_DIR):
    """Helper function to run volatility commands with proper error handling"""
    cmd = [VOLATILITY_PYTHON, VOLATILITY_SCRIPT] + cmd_args
    
    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=cwd  # Working directory
        )
        stdout, stderr = await process.communicate()
        
        if process.returncode != 0:
            stderr_text = stderr.decode('utf-8', errors='replace')
            return f"Error running Volatility command: {stderr_text}"
        
        return stdout.decode('utf-8', errors='replace')
    except Exception as e:
        return f"Exception running Volatility: {str(e)}"

@mcp.tool()
async def list_available_plugins() -> str:
    """List all available Volatility plugins"""
    return await run_volatility(["-h"])

@mcp.tool()
async def get_image_info(memory_dump_path: str) -> str:
    """
    Get information about a memory dump file
    
    Args:
        memory_dump_path: Full path to the memory dump file
    """
    # Validate the path exists
    memory_dump_path = os.path.normpath(memory_dump_path)
    if not os.path.isfile(memory_dump_path):
        return f"Error: Memory dump file not found at {memory_dump_path}"
    
    return await run_volatility(["-f", memory_dump_path, "windows.info.Info"])

@mcp.tool()
async def run_pstree(memory_dump_path: str) -> str:
    """
    Run the PsTree plugin to show process tree
    
    Args:
        memory_dump_path: Full path to the memory dump file
    """
    # Validate the path exists
    memory_dump_path = os.path.normpath(memory_dump_path)
    if not os.path.isfile(memory_dump_path):
        return f"Error: Memory dump file not found at {memory_dump_path}"
    
    return await run_volatility(["-f", memory_dump_path, "windows.pstree.PsTree"])

@mcp.tool()
async def run_pslist(memory_dump_path: str) -> str:
    """
    Run the PsList plugin to list processes
    
    Args:
        memory_dump_path: Full path to the memory dump file
    """
    # Validate the path exists
    memory_dump_path = os.path.normpath(memory_dump_path)
    if not os.path.isfile(memory_dump_path):
        return f"Error: Memory dump file not found at {memory_dump_path}"
    
    return await run_volatility(["-f", memory_dump_path, "windows.pslist.PsList"])

@mcp.tool()
async def run_psscan(memory_dump_path: str) -> str:
    """
    Run the PsScan plugin to scan for processes that might be hidden
    
    Args:
        memory_dump_path: Full path to the memory dump file
    """
    # Validate the path exists
    memory_dump_path = os.path.normpath(memory_dump_path)
    if not os.path.isfile(memory_dump_path):
        return f"Error: Memory dump file not found at {memory_dump_path}"
    
    return await run_volatility(["-f", memory_dump_path, "windows.psscan.PsScan"])

@mcp.tool()
async def run_netscan(memory_dump_path: str) -> str:
    """
    Run the NetScan plugin to show network connections
    
    Args:
        memory_dump_path: Full path to the memory dump file
    """
    # Validate the path exists
    memory_dump_path = os.path.normpath(memory_dump_path)
    if not os.path.isfile(memory_dump_path):
        return f"Error: Memory dump file not found at {memory_dump_path}"
    
    return await run_volatility(["-f", memory_dump_path, "windows.netscan.NetScan"])

@mcp.tool()
async def run_malfind(memory_dump_path: str, dump_dir: Optional[str] = None) -> str:
    """
    Run the MalFind plugin to detect injected code/DLLs
    
    Args:
        memory_dump_path: Full path to the memory dump file
        dump_dir: Optional directory to dump suspicious memory sections
    """
    # Validate the path exists
    memory_dump_path = os.path.normpath(memory_dump_path)
    if not os.path.isfile(memory_dump_path):
        return f"Error: Memory dump file not found at {memory_dump_path}"
    
    cmd_args = ["-f", memory_dump_path, "windows.malfind.Malfind"]
    
    if dump_dir:
        dump_dir = os.path.normpath(dump_dir)
        if not os.path.isdir(dump_dir):
            try:
                os.makedirs(dump_dir)
            except Exception as e:
                return f"Error creating dump directory: {str(e)}"
        cmd_args.extend(["--dump-dir", dump_dir])
    
    result = await run_volatility(cmd_args)
    
    if dump_dir and os.path.exists(dump_dir):
        dumped_files = os.listdir(dump_dir)
        if dumped_files:
            result += f"\n\nDumped {len(dumped_files)} suspicious memory sections to {dump_dir}"
    
    return result

@mcp.tool()
async def run_cmdline(memory_dump_path: str) -> str:
    """
    Run the CmdLine plugin to show process command line arguments
    
    Args:
        memory_dump_path: Full path to the memory dump file
    """
    # Validate the path exists
    memory_dump_path = os.path.normpath(memory_dump_path)
    if not os.path.isfile(memory_dump_path):
        return f"Error: Memory dump file not found at {memory_dump_path}"
    
    return await run_volatility(["-f", memory_dump_path, "windows.cmdline.CmdLine"])

@mcp.tool()
async def run_dlllist(memory_dump_path: str, pid: Optional[int] = None) -> str:
    """
    Run the DllList plugin to list loaded DLLs for processes
    
    Args:
        memory_dump_path: Full path to the memory dump file
        pid: Optional process ID to filter results
    """
    # Validate the path exists
    memory_dump_path = os.path.normpath(memory_dump_path)
    if not os.path.isfile(memory_dump_path):
        return f"Error: Memory dump file not found at {memory_dump_path}"
    
    cmd_args = ["-f", memory_dump_path, "windows.dlllist.DllList"]
    
    if pid is not None:
        cmd_args.extend(["--pid", str(pid)])
    
    return await run_volatility(cmd_args)

@mcp.tool()
async def run_handles(memory_dump_path: str, pid: Optional[int] = None) -> str:
    """
    Run the Handles plugin to list open handles for processes
    
    Args:
        memory_dump_path: Full path to the memory dump file
        pid: Optional process ID to filter results
    """
    # Validate the path exists
    memory_dump_path = os.path.normpath(memory_dump_path)
    if not os.path.isfile(memory_dump_path):
        return f"Error: Memory dump file not found at {memory_dump_path}"
    
    cmd_args = ["-f", memory_dump_path, "windows.handles.Handles"]
    
    if pid is not None:
        cmd_args.extend(["--pid", str(pid)])
    
    return await run_volatility(cmd_args)

@mcp.tool()
async def run_filescan(memory_dump_path: str) -> str:
    """
    Run the FileScan plugin to scan for file objects
    
    Args:
        memory_dump_path: Full path to the memory dump file
    """
    # Validate the path exists
    memory_dump_path = os.path.normpath(memory_dump_path)
    if not os.path.isfile(memory_dump_path):
        return f"Error: Memory dump file not found at {memory_dump_path}"
    
    return await run_volatility(["-f", memory_dump_path, "windows.filescan.FileScan"])

@mcp.tool()
async def run_memmap(memory_dump_path: str, pid: int) -> str:
    """
    Run the MemMap plugin to show memory map for a specific process
    
    Args:
        memory_dump_path: Full path to the memory dump file
        pid: Process ID to analyze
    """
    # Validate the path exists
    memory_dump_path = os.path.normpath(memory_dump_path)
    if not os.path.isfile(memory_dump_path):
        return f"Error: Memory dump file not found at {memory_dump_path}"
    
    return await run_volatility(["-f", memory_dump_path, "windows.memmap.Memmap", "--pid", str(pid)])

@mcp.tool()
async def run_custom_plugin(memory_dump_path: str, plugin_name: str, additional_args: str = "") -> str:
    """
    Run a custom Volatility plugin
    
    Args:
        memory_dump_path: Full path to the memory dump file
        plugin_name: Name of the plugin to run
        additional_args: Optional additional arguments for the plugin
    """
    # Validate the path exists
    memory_dump_path = os.path.normpath(memory_dump_path)
    if not os.path.isfile(memory_dump_path):
        return f"Error: Memory dump file not found at {memory_dump_path}"
    
    # Build the command arguments
    cmd_args = ["-f", memory_dump_path, plugin_name]
    
    # Add any additional arguments
    if additional_args:
        cmd_args.extend(additional_args.split())
    
    return await run_volatility(cmd_args)

@mcp.tool()
async def list_memory_dumps(search_dir: str = None) -> str:
    """
    List available memory dump files in a directory
    
    Args:
        search_dir: Directory to search for memory dumps (defaults to current directory)
    """
    if not search_dir:
        search_dir = os.getcwd()
    
    search_dir = os.path.normpath(search_dir)
    if not os.path.isdir(search_dir):
        return f"Error: Directory not found at {search_dir}"
    
    # Look for common memory dump extensions
    memory_extensions = ['.raw', '.vmem', '.dmp', '.mem', '.bin', '.img', '.001', '.dump']
    memory_files = []
    
    for root, _, files in os.walk(search_dir):
        for file in files:
            if any(file.lower().endswith(ext) for ext in memory_extensions):
                full_path = os.path.join(root, file)
                size_mb = os.path.getsize(full_path) / (1024 * 1024)
                memory_files.append(f"{full_path} (Size: {size_mb:.2f} MB)")
    
    if not memory_files:
        return f"No memory dump files found in {search_dir}"
    
    return "Found memory dump files:\n" + "\n".join(memory_files)

@mcp.resource("volatility://plugins")
async def get_volatility_plugins() -> str:
    """Get a list of all available Volatility plugins"""
    output = await run_volatility(["-h"])
    
    # Process the output to extract plugins
    plugins = []
    capture = False
    for line in output.split('\n'):
        if line.strip() == "Plugins":
            capture = True
            continue
        if capture and line.strip() == "":
            capture = False
            break
        if capture:
            plugins.append(line.strip())
    
    return json.dumps(plugins, indent=2)

@mcp.resource("volatility://help/{plugin}")
async def get_plugin_help(plugin: str) -> str:
    """Get help for a specific Volatility plugin"""
    return await run_volatility([plugin, "--help"])

# Run the server
if __name__ == "__main__":
    print(f"Starting Volatility MCP Server from: {VOLATILITY_DIR}")
    print(f"Using Python: {VOLATILITY_PYTHON}")
    print(f"Using Volatility script: {VOLATILITY_SCRIPT}")
    
    # Run the server
    mcp.run()