import sysdig
import execsnoop
import dummyMonitor

def Factory(logger, monitorTool = "sysdig", psListFilePath = None):
    tools = {
            "sysdig": sysdig.Sysdig,
            "execsnoop": execsnoop.Execsnoop,
            "FILE": dummyMonitor.DummyMonitor,
            }
    return tools[monitorTool](logger, psListFilePath)
