# IRPLogger
`IRPLogger` (IRP stands for I/O Request Packet) is a tool to monitor and log any I/O activity that occurs in the system. IRPLogger is implemented as a [File System Minifilter Drivers](http://msdn.microsoft.com/en-us/library/windows/hardware/ff540402).
IRPLogger is based on the [MiniSpy minifilter sample](https://github.com/Microsoft/Windows-driver-samples/tree/master/filesys/miniFilter/minispy).

IRPLogger-like tools have been used in academic research projects to capture ransomware filesystem behavior, like in [ShieldFS: A Self-healing, Ransomware-aware Filesystem](https://dl.acm.org/doi/10.1145/2991079.2991110). I developed this tool because it was necessary to re-implement these state-of-the-art detectors and to test our evasion attacks as shown in our paper [The Naked Sun: Malicious Cooperation Between Benign-Looking Processes](https://arxiv.org/abs/1911.02423) (accepted in ACNS '20).
 
### How to build
Follow Microsoft Driver Develpment's Kit [installation guide](https://docs.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk) to set up the environment.

### How to install
You can use the INF file provided to install, upgrade, and uninstall this file system filter driver. You can use the INF file alone or together with a batch file or a user-mode setup application. See [Using an INF File to Install a File System Filter Driver](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/using-an-inf-file-to-install-a-file-system-filter-driver) for more information.

Once installed, to load this minifilter, run: 

    fltmc load irplogger 
or 

    net start irplogger
    
In order to load this unsigned driver, make sure to disable the *driver signature verification*:
* Use *shutdown /r /o /t 0* and access the [Advanced Boot Options](https://support.microsoft.com/en-us/help/4026206/windows-get-to-safe-mode-and-other-startup-settings-in-windows-10 ).

**or**

* [install a test certificate](https://docs.microsoft.com/it-it/windows-hardware/drivers/install/makecert-test-certificate) in the Trusted Root Certification Authorities.
