# Dropbox Forensic Toolkit
This toolkit contains a guide to forensic analysis of Dropbox Cloud Sync utility. The investigations and development were based on Windows 10 Pro 64bit (Build 1809) and the Dropbox Basic client (v59.4.93)

See the `CheatSheet.md` file for a detailed guide on the forensic artefacts of Dropbox installations, as well as an approach to analysis.

## Autopsy Plugin
The Autopsy plugin has been designed to allow easy identification and extraction of key Dropbox database, configuration and cache files from a Windows image. This module will search for folders with key strings (that are unchangeable by the Dropbox installation), and use this information to derive the Dropbox sync folder path, as well as identify other key files.

### Installation (Windows)
This is a Python Module for Autopsy, and can be installed by downloading the containing folder `Dropbox Cloud Analysis Plugin` or by downloading the release ([https://github.com/HoganRichardson/dropboxforensics/releases/tag/1.0](https://github.com/HoganRichardson/dropboxforensics/releases/tag/1.0)) and placing it in `%userprofile\AppData\Roaming\autopsy\python_modules`.

Then, in Autopsy, navigate to Tools > Run Injest Modules > (select image). The "Dropbox Injest Module with UI" should appear in the list. Selecting it will show two checkboxes where you can choose to look for files and/or directories relating to Dropbox installations. Click "Finish" to run the modules. 

Once finished, any Dropbox-related files or directories will appear in the "Blackboard" (sidebar) under Interesting Items > Dropbox > Interesting Files.

![sidebar](https://user-images.githubusercontent.com/18340851/47053781-4b4a7480-d1fa-11e8-8092-1914dc1792c4.png)

## References
This project was aided by the work of [Francesco Picasso](http://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html?m=1) et. al., and utilises the tools available at [drfirfpi/decwindbx](https://github.com/dfirfpi/decwindbx)
