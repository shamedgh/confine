# Confine

This framework can generate Seccomp profiles for Docker images to harden
container and reduce the Linux kernel attack surface available to the
container.
The general goal is to 
remove functionalities not required by containers by performing static 
analysis.

***

## <img src="https://raw.githubusercontent.com/wiki/shamedgh/confine/images/about.png" alt="Confine overview figure" width=50 height=50/> About Confine
While you can find a more complete and thorough description of how Confine
works by reading our
[paper](https://www3.cs.stonybrook.edu/~sghavamnia/papers/confine.raid20.pdf),
we have summarized some of the most important points in this section. 
[Read more...](https://www3.cs.stonybrook.edu/~sghavamnia/confine/about.html)

***

## <img src="https://raw.githubusercontent.com/wiki/shamedgh/confine/images/installation.png" alt="Installation icon" width=50 height=50 /> Installation Guide
You can find the list of applications required to run Confine, along with
their relevant installation commands in this section.
[Read more...](https://www3.cs.stonybrook.edu/~sghavamnia/confine/installationguide.html)

***

## <img src="https://raw.githubusercontent.com/wiki/shamedgh/confine/images/userguide.png" alt="User guide icon" width=50 height=50 /> User Guide
The user guide provides a general overview of how to run different parts of
the toolchain and to generate the results provided in the paper.
[Read more...](https://www3.cs.stonybrook.edu/~sghavamnia/confine/userguide.html)

***

## <img src="https://raw.githubusercontent.com/wiki/shamedgh/confine/images/step-by-step.png" alt="step by step icon" width=60 height=50 style="float:left; margin-right: 1px;"/> Step-by-Step Guide
We also provide a step-by-step guide which walks you through running Confine
for a single Docker image, explaining what to expect in each of the program
execution.
[Read more...](https://www3.cs.stonybrook.edu/~sghavamnia/confine/stepbystep.html)

***

## Paper for reference:
Please consider citing our paper if you found our tool set useful.
```
@inproceedings{confineraid20,
year={2020},
booktitle={Proceedings of the International Conference on Research in Attacks,
Intrusions, and Defenses (RAID)},
title={Confine: Automated System Call Policy Generation for Container Attack
Surface Reduction},
author={Ghavamnia, Seyedhamed and Palit, Tapti and Benameur, Azzedine and
Polychronakis, Michalis}
}
```
