# Confine

This framework can help in debloating containers. This is a work in progress 
and each module has been described separately below. The general goal is to 
remove functionalities not required by containers by performing static 
analysis.

## Call Function Graph Extraction
We have used an LLVM pass to create a call function graph for musl-libc 
which maps all the exported functions to system calls. We also used the 
gcc RTL and the egypt tool to create a cfg for glibc.

## Container Profile Creation
The main script in this repo is the createProfiles.py file which uses 
previously created CFGs for musl-libc and glibc, along with a list of 
images and creates respective SECCOMP profiles for each.
-l: glibc callgraph
-m: musl-libc callgraph
-f: glibc shared object
-n: musl-libc shared object
-i: input file containing list of images
-o: path to store binaries and libraries extracted from container
-p: path to Docker default seccomp profile
-r: path to store results (seccomp profiles created)
-g: path to special cases containers like golang ones
-c: path to other CFGs, in case there are any other libraries with CFGs 
-d: debugging enabled or disabled
--finegrained: [Optional] Passing this argument enables the fine grained policy generation.
--allbinaries: [Optional] Passing this argument causes the extraction of all 
binaries instead of only the ones run during the 30 seconds. This would cause 
and extremely more conservative filter.


```
python3.7 createProfiles.py -l egypt/egypt-1.10/everything_graph.new -m callgraph.out -f output/nginx/libc.so.6 -n output/adminer/ld-musl-x86_64.so.1 -i images.list -o output/ -p default.seccomp.json -r results/ -g go.syscalls/ -c otherCfgs/ --finegrained --allbinaries -d
```

-i: The input file must have a special format as you can see in the example below:
```
16;mysql;mysql;['Databases'];903550824;Official;-e MYSQL_ROOT_PASSWORD=my-secret-pw
Rank;ImageName;Image-Download-Name;Categories;NumberOfDownloads;Official/UnOfficial;Extra Options(optional)
```
-g: If the container uses languages such as Golang and we have extracted system 
calls which are required through a different mechanism such as CFG extraction 
at the source code level, we can create a file named [imagename].syscalls and 
place it in the path specified by -g.

-c: In cases there might be libraries which also provide wrappers for system 
calls we can create the CFGs for these libraries as well and place them in 
the folder specicified by this option. These CFGs will also be used in case 
the optional --finegrained option is enabled and use them to create stricter 
syscall policies.

## Statistics Creator
After running the createProfiles.py script we can generate different statistics 
by running the createStats script.
-r: Path to the main summarized results
-e: Path to the detailed results
-i: Path to the image list used (to extract extra information which might not exist in results)
-o: path to store output
-c: file specifying system call for each cve
-b: path to where binaries and libraries for all containers exist (this should be the same as -o in createProfiles.py)
```
python3.7 createStats.py -r results/profile.report.csv -e results/profile.report.details.csv -i images.list -o stats/ -c cveToSyscall.csv -b output/
```

## Syscall Extractor
The extractSysCalls python script is the main function which takes the name of 
the required libc functions and the libc mapping file to create a seccomp 
profile.

```
python3.7 extractSysCalls.py -f nginx.container.nginxbashwlibs -c callgraph.out
```
The required functions should be in the format of one function per line.
The callgraph file should be in the format of one function call per line. e.g. 
a->b.

## Bash Scripts
There are a couple of bash scripts used to extract information and binaries 
from the container. The container should be running for these scripts to work.

### copyAllBins.sh
This script can be used to copy binaries from inside the container to the host. 
This script takes two arguments. The first argument a file which has the binary 
paths which should be copied from inside the container. The second argument 
should be the path to store the extracted files.

### copyAllBinsWithLibs.sh
This script can be used to copy binaries along with their dependent libraries 
from the container to the host. It also takes two arguments. The first argument 
a file which has the binary paths which should be copied from inside the 
container.

### extractAllImportedFuncs.sh
This script can be used to extract all the imported functions of ELF files. 
The folder of the ELF files can be passed as the first argument. The output 
file can be specified by the second argument.


## Prerequisites

This project has only been tested on Ubuntu 16.04. Due to usage of specific
debian-based tools (such as dpkg and apt-file) use on other operating systems
at your own risk.
All the scripts have been written in coordinance with python version 3.7.
```
sudo apt install python3.7
sudo apt install docker.io
sudo systemctl start docker
sudo systemctl enable docker
sudo apt install sysdig
```

## Authors

* **SeyedHamed Ghavamnia**

