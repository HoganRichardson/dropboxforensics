# This is free and unencumbered software released into the public domain.
#
# Anyone is free to copy, modify, publish, use, compile, sell, or
# distribute this software, either in source code form or as a compiled
# binary, for any purpose, commercial or non-commercial, and by any
# means.
#
# In jurisdictions that recognize copyright laws, the author or authors
# of this software dedicate any and all copyright interest in the
# software to the public domain. We make this dedication for the benefit
# of the public at large and to the detriment of our heirs and
# successors. We intend this dedication to be an overt act of
# relinquishment in perpetuity of all present and future rights to this
# software under copyright law.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
# OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
# ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.

#
# Ingest module for Autopsy with GUI
#
# Developed from a base template provided at https://github.com/sleuthkit/autopsy/tree/develop/pythonExamples
# 

import jarray
import inspect
from java.lang import System
from java.util.logging import Level
from javax.swing import JCheckBox
from javax.swing import BoxLayout
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.casemodule.services import Services
from org.sleuthkit.autopsy.ingest import DataSourceIngestModule
from org.sleuthkit.autopsy.ingest import FileIngestModule
from org.sleuthkit.autopsy.ingest import IngestMessage
from org.sleuthkit.autopsy.ingest import IngestModule
from org.sleuthkit.autopsy.ingest.IngestModule import IngestModuleException
from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter
from org.sleuthkit.autopsy.ingest import IngestModuleIngestJobSettings
from org.sleuthkit.autopsy.ingest import IngestModuleIngestJobSettingsPanel
from org.sleuthkit.autopsy.ingest import IngestServices
from org.sleuthkit.autopsy.ingest import IngestModuleGlobalSettingsPanel
from org.sleuthkit.datamodel import BlackboardArtifact
from org.sleuthkit.datamodel import BlackboardAttribute
from org.sleuthkit.datamodel import ReadContentInputStream
from org.sleuthkit.autopsy.coreutils import Logger
from java.lang import IllegalArgumentException

import json

class DropboxInjestWithUIFactory(IngestModuleFactoryAdapter):
    def __init__(self):
        self.settings = None

    moduleName = "Dropbox Injest Module with UI"

    def getModuleDisplayName(self):
        return self.moduleName

    def getModuleDescription(self):
        return "Module that attempts to identify current or previous Dropbox cloud storage installations"

    def getModuleVersionNumber(self):
        return "1.0"

    def getDefaultIngestJobSettings(self):
        return DropboxInjestWithUISettings()

    def hasIngestJobSettingsPanel(self):
        return True

    def getIngestJobSettingsPanel(self, settings):
        if not isinstance(settings, DropboxInjestWithUISettings):
            raise IllegalArgumentException("Expected settings argument to be instanceof DropboxInjestWithUISettings")
        self.settings = settings
        return DropboxInjestWithUISettingsPanel(self.settings)

    def isFileIngestModuleFactory(self):
        return True

    def createFileIngestModule(self, ingestOptions):
        return DropboxInjestWithUI(self.settings)


# File-level ingest module.  One gets created per thread.
# Looks at the attributes of the passed in file.
class DropboxInjestWithUI(FileIngestModule):
    
    _logger = Logger.getLogger(DropboxInjestWithUIFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    # Autopsy will pass in the settings from the UI panel
    def __init__(self, settings):
        self.local_settings = settings

    # Where any setup and configuration is done
    def startUp(self, context):
        # As an example, determine if user configured a flag in UI
        if self.local_settings.getFileFlag():
            self.log(Level.INFO, "Dropbox file flag is set")
        else:
            self.log(Level.INFO, "Dropbox file flag is not set")

        if self.local_settings.getDirFlag():
            self.log(Level.INFO, "Dropbox directory flag is set")
        else:
            self.log(Level.INFO, "Dropbox directory flag is not set")
        # Throw an IngestModule.IngestModuleException exception if there was a problem setting up
        # raise IngestModuleException("Oh No!")
        pass

    # Where the analysis is done.  Each file will be passed into here.
    def process(self, file):
        # See code in pythonExamples/fileIngestModule.py for example code
       
        # Create blackboard for all Dropbox files
        blackboard = Case.getCurrentCase().getServices().getBlackboard()

        ''' 
            Find and analyse CURRENT Dropbox installations
        '''
        # Look for the `info.json` file (Usually in %user%\AppData\Local\Dropbox)
        if self.local_settings.getFileFlag():
            if file.isFile():
                if file.getNameExtension() == "json": # Note if the extension is tampered with, this will miss it
                    if ("AppData/Local/Dropbox" in file.getParentPath()):
                        if (file.getName() == "info.json"):
                            # Add to blackboard
                            # Make an artifact on the blackboard.  TSK_INTERESTING_FILE_HIT is a generic type of
                            # artifact.  Refer to the developer docs for other examples.
                            self.log(Level.INFO, "Found Dropbox-related File: " + file.getName())
                            art = file.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT)
                            att = BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME,
                                DropboxInjestWithUIFactory.moduleName, "Dropbox")
                            art.addAttribute(att)

                            try:
                                # index the artifact for keyword search
                                blackboard.indexArtifact(art)

                            except Blackboard.BlackboardException as e:
                                self.log(Level.SEVERE, "Error indexing artifact " + art.getDisplayName())

                elif (file.getNameExtension() == "dbx"): # Note if the extension is tampered with, this will miss it
                    if ("AppData/Local/Dropbox" in file.getParentPath()):
                        if (file.getName() == "config.dbx" or 
                                file.getName() == "filecache.dbx" or file.getName() == "deleted.dbx"):
                                    self.log(Level.INFO, "Found Dropbox-related File: " + file.getName())

                                    art = file.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT)
                                    att = BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME,
                                          DropboxInjestWithUIFactory.moduleName, "Dropbox")
                                    art.addAttribute(att)

                                    try:
                                        # index the artifact for keyword search
                                        blackboard.indexArtifact(art)
                                    except Blackboard.BlackboardException as e:
                                        self.log(Level.SEVERE, "Error indexing artifact " + art.getDisplayName())

        elif self.local_settings.getDirFlag():
            if file.isDir():
                # Looking at directories
                if file.getName() == ".dropbox.cache":
                    self.log(Level.INFO, "Found Dropbox-related Folder: " + file.getName())

                    art = file.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT)
                    att = BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME,
                          DropboxInjestWithUIFactory.moduleName, "Dropbox")
                    art.addAttribute(att)

                    try:
                        # index the artifact for keyword search
                        blackboard.indexArtifact(art)
                    except Blackboard.BlackboardException as e:
                        self.log(Level.SEVERE, "Error indexing artifact " + art.getDisplayName())

                    # Add Parent Folder - this is the Dropbox sync folder
                    parent = file.getParent() 
                    self.log(Level.INFO, "Found Dropbox Sync Folder: " + parent.getName())

                    art = parent.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT)
                    att = BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME,
                          DropboxInjestWithUIFactory.moduleName, "Dropbox")
                    art.addAttribute(att)

                    try:
                        # index the artifact for keyword search
                        blackboard.indexArtifact(art)
                    except Blackboard.BlackboardException as e:
                        self.log(Level.SEVERE, "Error indexing artifact " + art.getDisplayName())


        return IngestModule.ProcessResult.OK

    # Where any shutdown code is run and resources are freed.
    def shutDown(self):
        pass

# Stores the settings that can be changed for each ingest job
# All fields in here must be serializable.  It will be written to disk.
class DropboxInjestWithUISettings(IngestModuleIngestJobSettings):
    serialVersionUID = 1L

    def __init__(self):
        self.file_flag = True 
        self.dir_flag = True

    def getVersionNumber(self):
        return serialVersionUID

    def getFileFlag(self):
        return self.file_flag

    def setFileFlag(self, flag):
        self.file_flag = flag

    def getDirFlag(self):
        return self.dir_flag

    def setDirFlag(self, flag):
        self.dir_flag = flag


# UI that is shown to user for each ingest job so they can configure the job.
class DropboxInjestWithUISettingsPanel(IngestModuleIngestJobSettingsPanel):
    # Note, we can't use a self.settings instance variable.
    # Rather, self.local_settings is used.
    # https://wiki.python.org/jython/UserGuide#javabean-properties
    # Jython Introspector generates a property - 'settings' on the basis
    # of getSettings() defined in this class. Since only getter function
    # is present, it creates a read-only 'settings' property. This auto-
    # generated read-only property overshadows the instance-variable -
    # 'settings'

    # We get passed in a previous version of the settings so that we can
    # prepopulate the UI
    def __init__(self, settings):
        self.local_settings = settings
        self.initComponents()
        self.customizeComponents()

    def checkBoxEvent(self, event):
        if self.file_checkbox.isSelected():
            self.local_settings.setFileFlag(True)
        else:
            self.local_settings.setFileFlag(False)

        if self.dir_checkbox.isSelected():
            self.local_settings.setDirFlag(True)
        else:
            self.local_settings.setDirFlag(False)

    def initComponents(self):
        self.setLayout(BoxLayout(self, BoxLayout.Y_AXIS))
        self.file_checkbox = JCheckBox("Look for Files relating to Dropbox", actionPerformed=self.checkBoxEvent)
        self.add(self.file_checkbox)

        self.dir_checkbox = JCheckBox("Look for Directories relating to Dropbox", actionPerformed=self.checkBoxEvent)
        self.add(self.dir_checkbox)

    def customizeComponents(self):
        self.file_checkbox.setSelected(self.local_settings.getFileFlag())
        self.dir_checkbox.setSelected(self.local_settings.getDirFlag())

    # Return the settings used
    def getSettings(self):
        return self.local_settings
