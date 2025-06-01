# README

## How to use the server

### Windows

#### setup in server dir

in your cmd:

* clone the repo: `git clone https://github.com/Yuanyuan4666/mcp_instance.git`
* jump into the server repo: `cd mcp_instance\server_inst\weather`
* setup the virtual environment: `uv venv`
* activate the virtual environment: `.venv\Scripts\activate`
* install dependencies: `uv add mcp[cli] httpx`

#### setup in your client dir

go to your claude or other client repo:

use claude for the example:

```
{
    "mcpServers": {
        "weather": {
            "command": "uv",
            "args": [
                "--directory",
                "C:\\ABSOLUTE\\PATH\\TO\\PARENT\\FOLDER\\weather",
                "run",
                "weather.py"
            ]
        }
    }
}
```

paste it into `Claude\claude_desktop_config.json`

## How to use it

in your client, find the tools, and ask a relative question

