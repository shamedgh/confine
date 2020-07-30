```
uname --kernel-release
```

```
sudo docker container ls -a
```

```
sudo docker run --name test1 -td nginx
```

```
sudo docker container ls -a
```

```
sudo docker run --name test1 -td nginx
```

```
sudo docker kill test1
```

```
sudo docker container ls -a
```

```
sudo docker rm test1
```

```
cd /home/ubuntu/confine
```

```
vim myimages.json
```

```
{
    "nginx": {
        "enable": "true",
        "image-name": "nginx",
        "image-url": "nginx",
        "dependencies": {}
    }
}
```

```
sudo python3.7 confine.py -l libc-callgraphs/glibc.callgraph -m libc-callgraphs/musllibc.callgraph -i myimages.json -o output/ -p default.seccomp.json -r results/ -g go.syscalls/
```

```
ls -lh ./output/nginx
```

```
cat ./results/nginx.seccomp.json
```

```
sudo docker run --name container-hardened --security-opt seccomp=results/nginx.seccomp.json -td nginx
```

```
sudo docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' container-hardened
```

```
wget http://[IP-Address]
cat index.html
```

```
sudo docker exec -it container-hardened /bin/bash
```

```
sudo docker exec -it container-hardened /bin/sh
```

```
whoami
date
ls
cp
```

```
apt-get update
```

```
cat results/nginx.seccomp.json | grep name
cat results/nginx.seccomp.json | grep name | wc -l
```

```
python3.7 filterProfileToCve.py -c cve.files/cveToStartNodes.csv.validated -f results/profile.report.details.csv -o results -v cve.files/cveToFile.json.type.csv --manualcvefile cve.files/cve.to.syscall.manual --manualtypefile cve.files/cve.to.vulntype.manual
```

```
cat results.container.csv
cat results.container.csv | grep False
```
