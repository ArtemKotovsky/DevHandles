# Device Handles
Enumerates system processes handles similar as the Process Exporer -> "Find Handle or DLL" does

### Features

#### Wildcard mask filtering by 
    * Process name 
    * Handle object type
    * Handle object name
    * Device name
    
Currently supports a list of filters separated by ';' - it means OR.
    
Example:
    DevHandles.exe --filter=*VID_8086*
    DevHandles.exe --filter=*.pdf
    DevHandles.exe --filter=explorer.exe
    DevHandles.exe --filter=File;Event
    DevHandles.exe --filter=\Device\Mup\*
    DevHandles.exe --filter=\REGISTRY\MACHINE\SOFTWARE\*;\REGISTRY\USER\*
    DevHandles.exe --filter=*VID_8086*;explorer.exe;File;\Device\Mup\*
    
#### Pooling for changes 

Checks what new has been opened in processes according to the filter settings and prints it.

Example:
    DevHandles.exe --filter=*VID_8086* --timeout=10
    DevHandles.exe --filter=\REGISTRY\MACHINE\SOFTWARE\* --timeout=10

Output:
    11:12:07 DevHandles.exe (16940) [Ref=1] Key \REGISTRY\MACHINE\SOFTWARE\Microsoft\Ole
    11:12:07 DevHandles.exe (16940) [Ref=1] Key \REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
    11:12:26 explorer.exe (8520) [Ref=1] Key \REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Render\{16a0d296-2f7c-4ceb-91cc-583b22c7c54f}\Properties

### Help
    
DevHandles.exe --help
Usage:
   --filter=[wildcard-mask-list] - use *? filers with ; splitter
   --timeout=[seconds] - enables monitoring by timeout
   --verbose,-v - extra logging

Examples:
   --filter=*VID_8086*;explorer.exe;File;*device* --timeout=10 --verbose
   --filter=*USB* --timeout=10
   --filter=\Device\Mup\* --timeout=10

### Checked Windows versions
#### Windows 10 x64 1909