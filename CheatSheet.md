# Dropbox Forensics Cheat Sheet
##### Developed by [Hogan Richardson](https://github.com/hoganrichardson)
##### Based on Windows 10 Pro (Build 1809) and Dropbox Basic (v59.4.93)
---
#### Contents
* [Dropbox File Structure](#dropbox-file-structure)
  * [Configuration Files](#configuration-files)
  * [Registry Keys](#registry-keys)
  * [Synchronised Files](#synchronised-files)
  * [Cache & Deleted Files](#cache--deleted-files)
* [Interpreting Dropbox Configuration Files](#interpreting-dropbox-configuration-files)
  * [info.json](#infojson)
  * [Decrypting *.dbx Files](#decrypting-dbx-files)
  * [config.dbx](#configdbx)
  * [filecache.dbx](#filecachedbx)
  * [deleted.dbx](#deleteddbx)
* [An Approach to Dropbox Analysis](#an-approach-to-dropbox-analysis)
---
## Dropbox File Structure
### Configuration Files
Dropbox places most of it's configuration files in the `%userprofile%\AppData\Local\Dropbox` directory. This includes various database files that describe the content/configuration (stored in encrypted `.dbx` files - however, some of these files are just base64 strings).

**Key Files in the Configuration File Structure**
```
%userprofile%\AppData\Local\Dropbox\
├── info.json
├── host.db
├── host.dbx
├── instance1\
│   ├── config.dbx
│   ├── deleted.dbx
│   └── filecache.dbx
```

### Registry Keys
The Dropbox installation adds various keys to the Windows registry, which will become important if you want to decrypt some of the database files.

**Dropbox Registry Keys**
```
NTUSER.DAT\
├── Software\
│   ├── Dropbox\
│   ├── ks\
│   │   ├── Client
│   │   └── Client-p
│   ├── ks1\
│   │   ├── Client
│   │   └── Client-p
│   └── InfPatchComplete
```

### Synchronised Files
Inside the Dropbox path (which does not necessarily have to exist in the common `%userprofile%\Dropbox` location), there are the synchronised files (specific directories can be specified for synchronisation using the Dropbox application).
Dropbox uses Alternate Data Streams to store metadata about these files. The following files are included for each file synchronised:
* `filename:com.dropbox.attrs`
* `filename:com.dropbox.attributes`

### Cache & Deleted Files
Additionally, there is a hidden `.dropbox.cache` directory in the Dropbox path location. This may include files that have been previously sync'd, but deleted remotely, as well as other cached files from the associated Dropbox account.

## Interpreting Dropbox Configuration Files
### `info.json`
The first key file to investigate is the `info.json` file, which describes the basic details of the Dropbox instance, including the synchronisation file path, and other user details.

**Sample `info.json` File**
```json
{
  "personal": {
    "path": "C:\\Users\\Cloud\\Dropbox",
    "subscription_type": "Basic",
    "host": 44992841808,
    "is_team": false
  }
}
```

### Decrypting `*.dbx` Files
Dropbox utilises [DPAPI](https://en.wikipedia.org/wiki/Data_Protection_API) to create an encryption key for these database files. These encryption keys can be derived from the Dropbox `client` registry keys, the `Protect` SID folder and the SHA1 of the User's password. It is also possible to derive these keys from a live machine.

**Offline Extraction**

Before starting the derivation of these DBX keys, you need the following items:
* SHA1 of the User's Password (There are some [alternative ways](https://github.com/gentilkiwi/mimikatz) of obtaining this if you don't know it)
* `NTUSER.DAT` Registry Hive
* Copy of the user's Protect directory (`%userprofile%\AppData\Roaming\Microsoft\Protect`)
  * Note the user's SID, which is the name of the subfolder in this directory
* The [`dbx-key-win-dpapi.py`](https://github.com/dfirfpi/decwindbx/blob/master/dbx-key-win-dpapi.py) script

Now, it is a simple, one-line process to run the script and obtain the key.
```bash
$ ./dbx-key-win-dpapi.py --masterkey=./Protect --ntuser=./NTUSER.DAT --sid=S-1-2-34-.... --credhist=./Protect/CREDHIST --hash=da39a3ee5e6b4b0d3255bfef95601890afd80709
```

The output will display the dbx key, which can then be used to decrypt any of the Dropbox `.dbx` files (those which are actually database files). To decrypt and output these files as `.db`, use the [`sqlite-dbx-win64.exe`](https://github.com/dfirfpi/decwindbx/blob/master/sqlite-dbx-win64.exe) tool.

```console
C:\> sqlite-dbx-win64.exe -key 56777b7313e7de61215b691ecae83609 deleted.dbx ".backup deleted.db"
```

**Using the Live Machine**

If you have access to a logged-in, live machine during acquisition, you may wish to run the live script. This will attempt to derive the DBX key from the live system.

* Obtain [`dbx-key-win-live.ps1`](https://github.com/dfirfpi/decwindbx/blob/master/dbx-key-win-live.ps1)
* Run PowerShell as Administrator
* Execute the following commands

```console
PS C:\> Set-ExecutionPolicy RemoteSigned
PS C:\> .\dbx-key-win-live.ps1
```

### `config.dbx`
This is the main configuration database file for the Dropbox instance. It contains the details of the Dropbox setup, including the Dropbox username. It is a SQLite database, however it is encrypted and thus requires some processing before it's data can be examined.
Once the decryption key is obtained (using the above method), the database can be opened in any SQLite browser. There is one table in the database, making it effectively a list of key-value pairs. Some noteworthy keys and example values are outlined below.

| Key | Value |
| --- | --- |
|userdisplayname|Your Name
|email|example@example.com
|dropbox_path|C:\Users\Me\Dropbox
|displayname|DESKTOP-AA01



### `filecache.dbx`
This database may contain information on cached files. From my investigations, this was a sparsely populated database that yielded little information.

Again, this database is encrypted, and uses the same key as above.

### `deleted.dbx`
This database contains a listing of some deleted files (whether it be locally or remotely), which can be helpful in getting an insight into what files have existed, but have since been removed, from the Dropbox sync directory. These files *may* be present in the Dropbox Cache file.

Once decrypted using the same key as above, this database contains two tables: "blocks" and "files". The "files" table contains details about any deleted files, including:
* file_id
* cache_path
* origin_path
* date_added
* size

## *An* Approach to Dropbox Analysis
1. Run my [Dropbox Autopsy Module](https://github.com/HoganRichardson/dropboxforensics/releases/tag/1.0) to find and identify the relevant Dropbox files for users on the system. Take a look at the `info.json` file for some basic information on the Dropbox installation if it was found.
2. Additionally, extract the `NTUSER.DAT` Registry Hives for each user on the system (stored in `%userprofile\NTUSER.DAT`).
3. Inspect the `.dropbox.cache` file, and potentially recover deleted Dropbox content.
4. Run the above mentioned decryption process to obtain access to the three key databse files: `config.dbx`, `filecache.dbx` and `deleted.dbx`
5. Identify the user's Dropbox account details, path and other useful details.
6. Identify and then attempt to recover any cached or deleted files pointed to in these databases.
7. Use timestamp information in these database files as part of timeline analysis.
