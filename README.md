# Volatility MCP Server

A Model Context Protocol (MCP) server that integrates Volatility 3 memory forensics framework with Claude and other MCP-compatible LLMs.

## Overview

This project bridges the powerful memory forensics capabilities of the Volatility 3 Framework with Large Language Models (LLMs) through the Model Context Protocol (MCP). It allows you to perform memory forensics analysis using natural language by exposing Volatility plugins as MCP tools that can be invoked directly by Claude or other MCP-compatible LLMs.

## Features

- **Natural Language Memory Forensics**: Ask Claude to analyze memory dumps using natural language
- **Process Analysis**: Examine running processes, parent-child relationships, and hidden processes
- **Network Forensics**: Identify network connections in memory dumps
- **Malware Detection**: Find potential code injection and other malicious artifacts
- **DLL Analysis**: Examine loaded DLLs and modules
- **File Objects**: Scan for file objects in memory
- **Custom Plugins**: Run any Volatility plugin with custom arguments
- **Memory Dump Discovery**: Automatically find memory dumps in a directory

## Requirements

- Python 3.10 or higher
- Volatility 3 Framework
- Claude Desktop or other MCP-compatible client
- MCP Python SDK (`mcp` package)

## Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/yourusername/volatility-mcp-server.git
   ```

2. Install the required Python packages:
   ```bash
   pip install mcp httpx
   ```

3. Configure the Volatility path in the script:
   - Open `volatility_mcp_server.py` and update the `VOLATILITY_DIR` variable to point to your Volatility 3 installation path.

4. Configure Claude Desktop:
   - Open your Claude Desktop configuration file located at:
     - Windows: `%APPDATA%\Claude\claude_desktop_config.json`
     - macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
   - Add the server configuration:
   ```json
   {
     "mcpServers": {
       "volatility": {
         "command": "python",
         "args": [
           "/path/to/volatility_mcp_server.py"
         ],
         "env": {
           "PYTHONPATH": "/path/to/volatility3"
         }
       }
     }
   }
   ```
   - Replace `/path/to/` with the actual path to your files.

5. Restart Claude Desktop to apply the changes.

## Usage

After setup, you can simply ask Claude natural language questions about your memory dumps:

- "List all processes in the memory dump at C:\path\to\dump.vmem"
- "Show me the network connections in C:\path\to\dump.vmem"
- "Run malfind to check for code injection in the memory dump"
- "What DLLs are loaded in process ID 4328?"
- "Check for hidden processes in C:\path\to\dump.vmem"

## Available Tools

The server exposes the following Volatility plugins as MCP tools:

1. `list_available_plugins` - Shows all Volatility plugins you can use
2. `get_image_info` - Provides information about a memory dump file
3. `run_pstree` - Shows the process hierarchy
4. `run_pslist` - Lists processes from the process list
5. `run_psscan` - Scans for processes including ones that might be hidden
6. `run_netscan` - Shows network connections in the memory dump
7. `run_malfind` - Detects potential code injection
8. `run_cmdline` - Shows command line arguments for processes
9. `run_dlllist` - Lists loaded DLLs for processes
10. `run_handles` - Shows file handles and other system handles
11. `run_filescan` - Scans for file objects in memory
12. `run_memmap` - Shows the memory map for a specific process
13. `run_custom_plugin` - Run any Volatility plugin with custom arguments
14. `list_memory_dumps` - Find memory dumps in a directory

## Memory Forensics Workflow

This MCP server enables a streamlined memory forensics workflow:

1. **Initial Triage**:
   - "Show me the process tree in memory.vmem"
   - "List all network connections in memory.vmem"

2. **Suspicious Process Investigation**:
   - "What command line was used to start process 1234?"
   - "Show me all the DLLs loaded by process 1234"
   - "What file handles are open in process 1234?"

3. **Malware Hunting**:
   - "Run malfind on memory.vmem to check for code injection"
   - "Show me processes with unusual parent-child relationships"
   - "Find hidden processes in memory.vmem"

## Troubleshooting

If you encounter issues:

1. **Path Problems**:
   - Make sure all paths are absolute and use double backslashes in Windows paths
   - Check that the memory dump file exists and is readable

2. **Permission Issues**:
   - Run Claude Desktop as Administrator
   - Check that Python and the Volatility directory have proper permissions

3. **Volatility Errors**:
   - Make sure Volatility 3 works correctly on its own
   - Try running the same command directly in your command line

4. **MCP Errors**:
   - Check Claude Desktop logs for MCP errors
   - Make sure the MCP Python package is installed correctly

## Extending

This server can be extended by:

1. Adding more Volatility plugins
2. Creating custom analysis workflows
3. Integrating with other forensic tools
4. Adding report generation capabilities

## License

[MIT License](LICENSE)

## Acknowledgments

- [Volatility Foundation](https://www.volatilityfoundation.org/) for the Volatility 3 Framework
- [Model Context Protocol](https://modelcontextprotocol.io/) for the MCP specification
- [Anthropic](https://www.anthropic.com/) for Claude

## Contact

If you have any questions or feedback, please open an issue on this repository.
