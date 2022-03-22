import sysdig
import execsnoop
import dummyMonitor

'''
To use bpfkprobe you need to install the prerequisites as described in:
# https://github.com/iovisor/bcc/blob/master/INSTALL.md#ubuntu---source
'''

def Factory(logger, monitorTool = "sysdig", psListFilePath = None):
    if ( monitorTool == "bpfkprobe" ):
        # pre-requisites of using bpfkprobe are too much, we shouldn't make Confine dependent on them
        import bpfKprobe
        return bpfKprobe.BpfKprobe(logger, psListFilePath)
    tools = {
            "sysdig": sysdig.Sysdig,
            "execsnoop": execsnoop.Execsnoop,
            "FILE": dummyMonitor.DummyMonitor,
            }
    return tools[monitorTool](logger, psListFilePath)
