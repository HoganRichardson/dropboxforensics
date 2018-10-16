# Dropbox Forensics Cheat Sheet
##### Developed by [Hogan Richardson](https://github.com/hoganrichardson)
##### Based on Windows 10 Pro (Build 1809) and Dropbox Basic (v59.4.93)

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

### `config.dbx`
This is the main configuration database file for the Dropbox instance. It contains the details of the Dropbox setup, including the Dropbox username. It is a SQLite database, however it is encrypted and thus requires some processing before it's data can be examined.

Dropbox utilises [DPAPI](https://en.wikipedia.org/wiki/Data_Protection_API) to create an encryption key for these database files. These encryption keys can be derived from the Dropbox `client` registry keys, the `Protect` #TODO CHECK THis and the ``

Once the decryption key is obtained, the database can be opened in any SQLite browser. There is one table in the database, making it effectively a list of key-value pairs. Some noteworthy keys and example values are outlined below.

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
This database contains a listing of all deleted files (whether it be locally or remotely) #TODO CHECK THIS, which can be helpful in getting an insight into what files have existed, but have since been removed, from the Dropbox sync directory. These files *may* be present in the Dropbox Cache file.

Once decrypted using the same key as above, this database contains two tables: "blocks" and "files". The "files" table contains details about any deleted files, including:
* file_id
* cache_path
* origin_path
* date_added
* size

## *An* Approach to Dropbox Analysis
1. Run my [Dropbox Autopsy Module]() to find and identify the relevant Dropbox files for users on the system.
2. Additionally, extract the `NTUSER.DAT` Registry Hives for each user on the system.
3.
