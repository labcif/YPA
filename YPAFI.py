
import jarray
import inspect
import os
import subprocess
import time
import json
import sys
import csv

from javax.swing import JCheckBox
from javax.swing import JList
from javax.swing import JTextArea
from javax.swing import BoxLayout
from java.awt import GridLayout
from java.awt import BorderLayout
from javax.swing import BorderFactory
from javax.swing import JToolBar
from javax.swing import JPanel
from javax.swing import JFrame
from javax.swing import JScrollPane
from javax.swing import JComponent
from java.awt.event import KeyListener
from org.python.core.util import StringUtil
from java.lang import Class
from java.lang import System
from java.sql import DriverManager, SQLException
from java.util.logging import Level
from java.io import File
from org.sleuthkit.datamodel import SleuthkitCase
from org.sleuthkit.datamodel import AbstractFile
from org.sleuthkit.autopsy.casemodule.services import Blackboard
from org.sleuthkit.datamodel import ReadContentInputStream
from org.sleuthkit.datamodel import BlackboardArtifact
from org.sleuthkit.datamodel import BlackboardAttribute
from org.sleuthkit.autopsy.ingest import IngestModule
from org.sleuthkit.autopsy.ingest.IngestModule import IngestModuleException
from org.sleuthkit.autopsy.ingest import DataSourceIngestModule
from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter
from org.sleuthkit.autopsy.ingest import IngestModuleIngestJobSettings
from org.sleuthkit.autopsy.ingest import IngestModuleIngestJobSettingsPanel
from org.sleuthkit.autopsy.ingest import IngestMessage
from org.sleuthkit.autopsy.ingest import IngestServices
from org.sleuthkit.autopsy.ingest import ModuleDataEvent
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.coreutils import PlatformUtil
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.casemodule.services import Services
from org.sleuthkit.autopsy.casemodule.services import FileManager
from org.sleuthkit.autopsy.datamodel import ContentUtils

# Factory that defines the name and details of the module and allows Autopsy
# to create instances of the modules that will do the analysis.


class YourPhoneIngestModuleFactory(IngestModuleFactoryAdapter):

    def __init__(self):
        self.settings = None

    moduleName = "Windows 'Your Phone' Analyzer"

    def getModuleDisplayName(self):
        return self.moduleName

    def getModuleDescription(self):
        return "Parses and analyzes information regarding Windows 10's 'Your Phone' App"

    def getModuleVersionNumber(self):
        return "0.1"

    def getDefaultIngestJobSettings(self):
        return YourPhoneWithUISettings()

    def hasIngestJobSettingsPanel(self):
        return True

    def getIngestJobSettingsPanel(self, settings):
        if not isinstance(settings, YourPhoneWithUISettings):
            raise IllegalArgumentException("Expected settings argument to be instanceof YourPhoneWithUISettings")
        self.settings = settings
        return YourPhoneWithUISettingsPanel(self.settings)

    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return YourPhoneIngestModule(self.settings)

# Data Source-level ingest module.  One gets created per data source.


class YourPhoneIngestModule(DataSourceIngestModule):

    _logger = Logger.getLogger(YourPhoneIngestModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__,
                          inspect.stack()[1][3], msg)

    def __init__(self, settings):
        self.context = None
        self.local_settings = settings
        self.art_list = []

    def create_temp_directory(self, dir):
        try:
            os.mkdir(self.temp_dir + dir)
        except:
            self.log(Level.INFO, "ERROR: " + dir + " directory already exists")

    def index_artifact(self, blackboard, artifact, artifact_type):
        try:
            # Index the artifact for keyword search
            blackboard.indexArtifact(artifact)
        except Blackboard.BlackboardException as e:
            self.log(Level.SEVERE, "Error indexing artifact " +
                     artifact.getDisplayName())
        # Fire an event to notify the UI and others that there is a new log artifact
        IngestServices.getInstance().fireModuleDataEvent(
            ModuleDataEvent(YourPhoneIngestModuleFactory.moduleName,
                            artifact_type, None))

    def create_artifact_type(self, art_name, art_desc, skCase):
        try:
            skCase.addBlackboardArtifactType(art_name, "YPA: " + art_desc)
        except:
            self.log(Level.INFO, "ERROR creating artifact type: " + art_desc)
        art = skCase.getArtifactType(art_name)
        self.art_list.append(art)
        return art

    def create_attribute_type(self, att_name, type, att_desc, skCase):
        try:
            skCase.addArtifactAttributeType(att_name, type, att_desc)
        except:
            self.log(Level.INFO, "ERROR creating attribute type: " + att_desc)
        return skCase.getAttributeType(att_name)

    # Where any setup and configuration is done
    # 'context' is an instance of org.sleuthkit.autopsy.ingest.IngestJobContext.
    # See: http://sleuthkit.org/autopsy/docs/api-docs/3.1/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_ingest_job_context.html
    def startUp(self, context):
        skCase = Case.getCurrentCase().getSleuthkitCase()
        self.temp_dir = Case.getCurrentCase().getTempDirectory()
        if PlatformUtil.isWindowsOS():
            self.path_to_exe = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ypa.exe")
            self.path_to_undark = os.path.join(os.path.dirname(os.path.abspath(__file__)), "undark.exe")
            if not os.path.exists(self.path_to_exe):
                raise IngestModuleException("EXE was not found in module folder")                   
        self.art_contacts = self.create_artifact_type("YPA_CONTACTS","Your Phone App Contacts",skCase)
        self.art_messages = self.create_artifact_type("YPA_MESSAGE","Your Phone App SMS",skCase)
        self.art_pictures = self.create_artifact_type("YPA_PICTURES","Your Phone Recent Pictures",skCase)
        self.art_freespace = self.create_artifact_type("YPA_FREESPACE","Your Phone Rows Recovered",skCase)

        self.att_contact_id = self.create_attribute_type('YPA_CONTACT_ID', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Contact id", skCase)
        self.att_address = self.create_attribute_type('YPA_ADDRESS', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Address", skCase)
        self.att_display_name = self.create_attribute_type('YPA_DISPLAY_NAME', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Display name", skCase)
        self.att_address_type = self.create_attribute_type('YPA_ADDRESS_TYPE', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Address type", skCase)
        self.att_times_contacted = self.create_attribute_type('YPA_TIMES_CONTACTED', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Times contacted", skCase)
        self.att_last_contact_time = self.create_attribute_type('YPA_LAST_CONTACT_TIME', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Last contact time", skCase) 
        self.att_last_update_time = self.create_attribute_type('YPA_LAST_UPDATE_TIME', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Last update time", skCase) 

        self.att_thread_id = self.create_attribute_type('YPA_THREAD_ID', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Thread id", skCase) 
        self.att_message_id = self.create_attribute_type('YPA_MESSAGE_ID', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Message id", skCase) 
        self.att_recipient_list = self.create_attribute_type('YPA_RECIPIENT_LIST', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Recipients", skCase) 
        self.att_from_address = self.create_attribute_type('YPA_FROM_ADDRESS', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING , "Address", skCase) 
        self.att_display_name = self.create_attribute_type('YPA_DISPLAY_NAME', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Display name", skCase) 
        self.att_body = self.create_attribute_type('YPA_BODY', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Message Body", skCase) 
        self.att_status = self.create_attribute_type('YPA_STATUS', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Status", skCase)         
        self.att_timestamp = self.create_attribute_type('YPA_TIMESTAMP', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Timestamp", skCase)      
     
        self.att_pic_size = self.create_attribute_type('YPA_PIC_SIZE', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.LONG, "Picture size (B)", skCase)

        self.att_rec_row = self.create_attribute_type('YPA_REC_ROW', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Data recovered from unvacuumed row", skCase)
        
        
        

        
    # Where the analysis is done.
    # The 'dataSource' object being passed in is of type org.sleuthkit.datamodel.Content.
    # See: http://www.sleuthkit.org/sleuthkit/docs/jni-docs/interfaceorg_1_1sleuthkit_1_1datamodel_1_1_content.html
    # 'progressBar' is of type org.sleuthkit.autopsy.ingest.DataSourceIngestModuleProgress
    # See: http://sleuthkit.org/autopsy/docs/api-docs/3.1/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_data_source_ingest_module_progress.html

    def process(self, dataSource, progressBar):
        blackboard = Case.getCurrentCase().getServices().getBlackboard()
        skCase = Case.getCurrentCase().getSleuthkitCase()
        fileManager = Case.getCurrentCase().getServices().getFileManager()
        
        files = fileManager.findFiles(dataSource, "phone.db") 
        numFiles = len(files)
        self.log(Level.INFO, "found " + str(numFiles) + " files")
        fileCount = 0
        for file in files:
            dbPath = os.path.join(self.temp_dir , str(file.getName()))
            ContentUtils.writeToFile(file, File(dbPath))
            try:
                subprocess.Popen([self.path_to_exe, dbPath,self.temp_dir+'\\']).communicate()[0]
            except Exception  as e:
                self.log(Level.INFO, "failed to open of the the files found, starting next one")
                continue
            try:
                with open(self.temp_dir+'\\'+'contacts.csv','rb') as conFile:
                    creader = csv.reader(conFile,delimiter=',',quotechar='"')
                    ignoreFirst = True
                    for row in creader:
                        if ignoreFirst:
                            ignoreFirst = False
                            continue
                        art = file.newArtifact(self.art_contacts.getTypeID())
                        art.addAttribute(BlackboardAttribute(self.att_contact_id, YourPhoneIngestModuleFactory.moduleName, row[0]))
                        art.addAttribute(BlackboardAttribute(self.att_address, YourPhoneIngestModuleFactory.moduleName, row[1]))
                        art.addAttribute(BlackboardAttribute(self.att_display_name, YourPhoneIngestModuleFactory.moduleName, row[2].decode('utf-8')))
                        art.addAttribute(BlackboardAttribute(self.att_address_type, YourPhoneIngestModuleFactory.moduleName, row[3]))
                        art.addAttribute(BlackboardAttribute(self.att_times_contacted, YourPhoneIngestModuleFactory.moduleName, row[4]))
                        art.addAttribute(BlackboardAttribute(self.att_last_contact_time, YourPhoneIngestModuleFactory.moduleName, row[5]))
                        art.addAttribute(BlackboardAttribute(self.att_last_update_time, YourPhoneIngestModuleFactory.moduleName, row[6]))
                        self.index_artifact(blackboard, art,self.art_contacts)
                with open(self.temp_dir+'\\'+'messages.csv','rb') as conFile:
                    creader = csv.reader(conFile,delimiter=',',quotechar='"')
                    ignoreFirst = True
                    for row in creader:
                        if ignoreFirst:
                            ignoreFirst = False
                            continue
                        art = file.newArtifact(self.art_messages.getTypeID())
                        art.addAttribute(BlackboardAttribute(self.att_thread_id, YourPhoneIngestModuleFactory.moduleName, row[0]))
                        art.addAttribute(BlackboardAttribute(self.att_message_id, YourPhoneIngestModuleFactory.moduleName, row[1]))
                        art.addAttribute(BlackboardAttribute(self.att_recipient_list, YourPhoneIngestModuleFactory.moduleName, row[2]))
                        art.addAttribute(BlackboardAttribute(self.att_from_address, YourPhoneIngestModuleFactory.moduleName, row[6]))
                        art.addAttribute(BlackboardAttribute(self.att_display_name, YourPhoneIngestModuleFactory.moduleName, row[3]))
                        art.addAttribute(BlackboardAttribute(self.att_body, YourPhoneIngestModuleFactory.moduleName, row[4].decode('utf-8')))
                        art.addAttribute(BlackboardAttribute(self.att_status, YourPhoneIngestModuleFactory.moduleName, row[5]))
                        art.addAttribute(BlackboardAttribute(self.att_timestamp, YourPhoneIngestModuleFactory.moduleName, row[7]))
                        self.index_artifact(blackboard, art,self.art_messages)
                try:
                    with open(self.temp_dir+'\\freespace.txt','w') as f:
                        subprocess.Popen([self.path_to_undark,'-i', dbPath, '--freespace'],stdout=f).communicate()
                    with open(self.temp_dir+'\\freespace.txt','r') as f:
                        self.log(Level.INFO, ' '.join([self.path_to_undark,'-i', dbPath, '--freespace >']))
                        self.log(Level.INFO, "called undark")
                        line = f.readline()
                        while line:
                            self.log(Level.INFO, "opened result")
                            art = file.newArtifact(self.art_freespace.getTypeID())
                            art.addAttribute(BlackboardAttribute(self.att_rec_row, YourPhoneIngestModuleFactory.moduleName, str(line)))
                            self.index_artifact(blackboard, art,self.art_freespace)
                            line = f.readline()
                except Exception  as e:
                    self.log(Level.INFO, "failed to read freespace data")
                    pass
            except Exception as e:
                self.log(Level.INFO, "failed to open of the the csv files generated, starting next one")
                pass
            finally:
                os.remove(self.temp_dir+'\\'+'contacts.csv')
                os.remove(self.temp_dir+'\\'+'messages.csv')
                os.remove(dbPath)
            try:
                full_path = (file.getParentPath() + file.getName()) 
                split = full_path.split('/')
                guidPath = '/'.join(split[:-3])
                usrPath = guidPath+'/User'       
                self.log(Level.INFO, usrPath)
                ufiles = fileManager.findFiles(dataSource, '%', usrPath)
                self.log(Level.INFO, ufiles[0].getName())
                for ufile in ufiles:
                    rpPath = ufile.getParentPath() + ufile.getName() +'/Recent Photos/' 
                    picfiles = fileManager.findFiles(dataSource, '%', rpPath)
                    for pic in picfiles:
                        self.log(Level.INFO, pic.getName())
                        # Make an artifact
                        art = pic.newArtifact(self.art_pictures.getTypeID())
                                    # Register file size
                        art.addAttribute(BlackboardAttribute(self.att_pic_size, YourPhoneIngestModuleFactory.moduleName, pic.getSize()))
                        self.index_artifact(blackboard, art, self.art_pictures)
            except Exception as e:
                self.log(Level.INFO, "failed to open of the the csv files generated, starting next one")
                continue
            
        return IngestModule.ProcessResult.OK   

class YourPhoneWithUISettings(IngestModuleIngestJobSettings): # These are just in case we end up needing an UI
    serialVersionUID = 1L
    
    def __init__(self):
        self.flag = False
        self.flag1 = False
        self.flag2 = False

    def getVersionNumber(self):
        return serialVersionUID

    # TODO: Define getters and settings for data you want to store from UI
    def getRawFlag(self):
        return self.flag

    def setFlag(self, flag):
        self.flag = flag

    def getRegistryFlag(self):
        return self.flag1

    def setFlag1(self, flag1):
        self.flag1 = flag1

    def getAnomaliesFlag(self):
        return self.flag2

    def setFlag2(self, flag2):
        self.flag2 = flag2

# UI that is shown to user for each ingest job so they can configure the job.


class YourPhoneWithUISettingsPanel(IngestModuleIngestJobSettingsPanel): # These are just in case we end up needing an UI
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
    # TODO: Update this for your UI
    def __init__(self, settings):
        self.local_settings = settings
        self.initComponents()
        self.customizeComponents()

    # TODO: Update this for your UI
    def checkBoxEvent(self, event):
        if self.checkbox.isSelected():
            self.local_settings.setFlag(True)
        else:
            self.local_settings.setFlag(False)
        if self.checkbox1.isSelected():
            self.local_settings.setFlag1(True)
        else:
            self.local_settings.setFlag1(False)
        if self.checkbox2.isSelected():
            self.local_settings.setFlag2(True)
        else:
            self.local_settings.setFlag2(False)

    # TODO: Update this for your UI

    def initComponents(self):
        self.setLayout(BoxLayout(self, BoxLayout.Y_AXIS))
        # self.setLayout(GridLayout(0,1))
        self.setAlignmentX(JComponent.LEFT_ALIGNMENT)
        self.panel1 = JPanel()
        self.panel1.setLayout(BoxLayout(self.panel1, BoxLayout.Y_AXIS))
        self.panel1.setAlignmentY(JComponent.LEFT_ALIGNMENT)
        self.checkbox = JCheckBox(
            "Extract raw table", actionPerformed=self.checkBoxEvent)
        self.checkbox1 = JCheckBox(
            "Search ntuser.dat for matches", actionPerformed=self.checkBoxEvent)
        self.checkbox2 = JCheckBox(
            "Search for date-time anomalies (this may take a few minutes more)", actionPerformed=self.checkBoxEvent)
        self.panel1.add(self.checkbox)
        self.panel1.add(self.checkbox1)
        self.panel1.add(self.checkbox2)
        self.add(self.panel1)

    # TODO: Update this for your UI

    def customizeComponents(self):
        self.checkbox.setSelected(self.local_settings.getRawFlag())
        self.checkbox1.setSelected(self.local_settings.getRegistryFlag())
        self.checkbox2.setSelected(self.local_settings.getAnomaliesFlag())

    # Return the settings used
    def getSettings(self):
        return self.local_settings