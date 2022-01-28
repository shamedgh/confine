import sysdig
import execsnoop
import dummyMonitor
import bpfKprobe

def Factory(logger, monitorTool = "sysdig", psListFilePath = None):
    tools = {
            "sysdig": sysdig.Sysdig,
            "execsnoop": execsnoop.Execsnoop,
            "FILE": dummyMonitor.DummyMonitor,
            "bpfkprobe": bpfKprobe.BpfKprobe,
            }
    return tools[monitorTool](logger, psListFilePath)
