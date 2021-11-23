import sysdig
import execsnoop
import bpfKprobe

def Factory(logger, monitorTool = "sysdig"):
    tools = {
            "sysdig": sysdig.Sysdig,
            "execsnoop": execsnoop.Execsnoop,
            "bpfkprobe": bpfKprobe.BpfKprobe,
            }
    return tools[monitorTool](logger)
