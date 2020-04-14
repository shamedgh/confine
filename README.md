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


## CVE to CFG Mapping
Extracting and mapping CVEs to parts of open source programs can be done 
by using this part of the repository. 
It can be used entirely separately from the rest 
and it doesn't have any direct dependency on debloating a container or 
kernel. This part might be moved to a independent repository later.
The goal of this part is to automatically map CVEs to functions in the 
call graph. This allows us to provide statistics on the number of CVEs 
mitigated as a result of removing parts of the code.
The process can be divided into two main phases, phase one, extracting the 
CVEs and their details from a publicly available website (currently 
cvedetails.com) and phase two, mapping them to functions in the graph.

###Prerequisites
sudo pip3 install bs4
sudo pip3 install lxml

(In case you have python3.6 and want to install for python3.7)
sudo python3.7 -m pip install bs4
sudo python3.7 -m pip install lxml

###CVE Scraping
The scraping consists of two main steps. In the first step we scrape the 
search results page of a CVE database website.
The URL should be provided by the user as a command-line option and should 
require a page ID which should be replaced with a {} so we can 
iterate over the results in different pages. In this step we only extract 
the URLs for the details pages of all the CVEs. 
In the second step, we start scraping the webpage for each of 
them looking for specific commit details. In the case of the Linux kernel 
we only look for links to git.kernel.org and have parsers for that website. 
But this can be extended to support other git online websites and formats.
The output of this section is a multi-level dictionary in the following 
format:
dict[cveId][commitId][file] = line number
We dump this dictionary and use it to extract the function names relevant 
to each CVE.

The CVE scraping can be run by using the following command:
```
python3.7 cveToFileMapper.py -u [cve-search-page-url] -n 40 -o cveToFile.json -d
```
-u: search page URL
-n: total number of pages
-o: dump file of dictionary
-d: debug enabled/disabled

###Mapper
This phase maps the CVEs extracted in the previous set to specific functions 
in the repository. An important point to keep in mind is that the commits 
related to each CVE might not be the most current of each file affected by 
that commit. And the commit message only specifies the file name and line 
number. So, we have to make sure the file we are using the same version 
which is specified by the commit to extract the correct function name for 
the filename and line number combination.
That's why we need to have access to the relevant repository for this section 
to work. When we parse the dictionary dump acquired in the previous phase, 
we use the commit ID to checkout the correct version of the file before 
trying to idenfity the related function.
After checking out the file, we use cscope to extract function definitions and 
line numbers and map the line number in the CVE commit message to the correct 
function. 
Last we create a CSV file consisting of the CVE and its relevant function name 
and line number.

The CVE to function mapping can be done by using the following command:
```
python3 cveToFunctionMapper.py -r /home/hamed/linux-kernel/linux/ -c /home/hamed/container-debloating/cveToFile.json -d
```
-r: repo path
-c: dictionary dump created in the previous step
-d: debug disabled/enabled

###CFG and Debloating
The final step which can be used if the CVEs are being extracted to measure 
debloating effectiveness is to count number of CVEs mitigated due to removal 
of a set of functions from the CFG.
```
python3.7 cfgToCveMapper.py -c linux.kernel.wo.ia32compat.cleaned.cfg -f syscall.starts.txt -v cvetofile.new.csv -d
```
-c: call function graph
-f: list of starting points in call graph which we want to extract CVEs for
-v: output of cveToFunctionMapper.py which is a csv in the following format cveid,commitid,filename,linenumber,functionname
-i: inverse the results, show CVEs related to all functions not in the specified file
-d: debug enabled/disabled

##CFG Manipulation
The graph class can generally be used for any graph operations. We have 
gathered a set of pre-defined functionalities which are used in manipulating 
the call graph, which have been explained below:

### Function Pointer Analysis ###
There are cases which functions are only assigned to function pointers in certain 
paths of the call graph which aren't accessible from a specific starting 
point. In these cases, if the functions aren't ever called directly, since 
the point where their address is being taken is never reached in our respective 
path, we can remove any indirect invocations of these functions. We first 
need to run a Simple Program Analysis using our customized SVF, to create a 
graph showing where each function's address is being taken and use it to 
prune the graph.

```
python3.7 graphCleaner.py --fpanalysis --funcname main --output tmp.cfg --directgraphfile ~/webserver-asr/process-separation/scripts/httpd.svf.conditional.direct.calls.cfg --funcpointerfile ~/webserver-asr/process-separation/scripts/httpd.function.pointer.allocations.cfg -c ~/webserver-asr/process-separation/scripts/httpd.apr.svf.type.cfg
```
--fpanalysis: specifies we want to run the function pointer analysis
-c: initial call function graph
--output: path to store pruned CFG
--directgraphfile: path to CFG with direct function calls ONLY
--funcpointerfile: path to file consisting function pointer assignments (SPA result)
--funcname: function name which is our starting point (e.g. main)


### Condition Edge Removal ###
```
python3.7 graphCleaner.py --minremovable -c ~/webserver-asr/process-separation/scripts/httpd.apr.svf.type.fp.cfg --minremovestart main --minremoveend apr_proc_create --conditionalgraphfile ~/webserver-asr/process-separation/scripts/httpd.svf.conditional.direct.calls.cfg --minremovemaxdepth 10
```

## Prerequisites

This project has only been tested on Ubuntu 16.04. Due to usage of specific
debian-based tools (such as dpkg and apt-file) use on other operating systems
at your own risk.
All the scripts have been written in coordinance with python version 3.7.
```
sudo apt install docker.io
sudo systemctl start docker
sudo systemctl enable docker
sudo apt install sysdig
```

## Authors

* **SeyedHamed Ghavamnia**

