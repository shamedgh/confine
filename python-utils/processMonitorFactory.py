import sysdig
import execsnoop

def Factory(logger, monitorTool = "sysdig"):
    tools = {
            "sysdig": sysdig.Sysdig,
            "execsnoop": execsnoop.Execsnoop,
            }
    return tools[monitorTool](logger)
