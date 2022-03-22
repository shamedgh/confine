import sysdig
import execsnoop
import dummyMonitor
import bpfKprobe

'''
To use bpfkprobe you need to install the prerequisites as described in:
# https://github.com/iovisor/bcc/blob/master/INSTALL.md#ubuntu---source
'''

def Factory(logger, monitorTool = "sysdig", psListFilePath = None):
    tools = {
            "sysdig": sysdig.Sysdig,
            "execsnoop": execsnoop.Execsnoop,
            "FILE": dummyMonitor.DummyMonitor,
            "bpfkprobe": bpfKprobe.BpfKprobe,   
            }
    return tools[monitorTool](logger, psListFilePath)
