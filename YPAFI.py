import jarray
import inspect
import os
import subprocess
import time
import json
import sys
import csv
import mdgMod

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
from org.sqlite import SQLiteConfig, SQLiteOpenMode
from org.sqlite.SQLiteConfig import JournalMode
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
from org.sleuthkit.autopsy.coreutils.MessageNotifyUtil import Message

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
        except Blackboard.BlackboardException:
            self.log(Level.INFO, "Error indexing artifact " +
                     artifact.getDisplayName())
        # Fire an event to notify the UI and others that there is a new log artifact
        IngestServices.getInstance().fireModuleDataEvent(
            ModuleDataEvent(YourPhoneIngestModuleFactory.moduleName,
                            artifact_type, None))

    def create_artifact_type(self, art_name, art_desc, skCase):
        try:
            skCase.addBlackboardArtifactType(art_name, "YPA: " + art_desc)
        except:
            self.log(Level.INFO, "Error creating artifact type: " + art_desc)
        art = skCase.getArtifactType(art_name)
        self.art_list.append(art)
        return art

    def create_attribute_type(self, att_name, type, att_desc, skCase):
        try:
            skCase.addArtifactAttributeType(att_name, type, att_desc)
        except:
            self.log(Level.INFO, "Error creating attribute type: " + att_desc)
        return skCase.getAttributeType(att_name)

    def execute_query(self, query, db):
        try:
            return db.createStatement().executeQuery(query)
        except SQLException as e:
            self.log(Level.SEVERE, "Failed to execute query: " + query + ", due to " + str(e))
        return

    def create_db_conn(self, file):
        dbPath = os.path.join(self.temp_dir , str(file.getName()))
        ContentUtils.writeToFile(file, File(dbPath))
        try:
            Class.forName("org.sqlite.JDBC").newInstance()
            config = SQLiteConfig()
            config.setEncoding(SQLiteConfig.Encoding.UTF8)
            config.setJournalMode(JournalMode.WAL)
            config.setReadOnly(True)
            return DriverManager.getConnection(
                "jdbc:sqlite:%s" % dbPath, config.toProperties()), dbPath
        except Exception as e:
            self.log(Level.SEVERE, "Could not create database connection for " +
                        dbPath + " (" + str(e) + ")")
        return None, dbPath
    
    def close_db_conn(self, db_conn, db_path):
        db_conn.close()
        try:
            os.remove(db_path)
        except (Exception, OSError) as e:
            self.log(Level.SEVERE, "Error deleting temporary DB: " + str(e))

    # Where any setup and configuration is done
    # 'context' is an instance of org.sleuthkit.autopsy.ingest.IngestJobContext.
    # See: http://sleuthkit.org/autopsy/docs/api-docs/3.1/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_ingest_job_context.html
    def startUp(self, context):
        skCase = Case.getCurrentCase().getSleuthkitCase()
        self.temp_dir = Case.getCurrentCase().getTempDirectory()
        if PlatformUtil.isWindowsOS():
            #self.path_to_exe = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ypa.exe") #OLD
            self.path_to_undark = os.path.join(os.path.dirname(os.path.abspath(__file__)), "undark.exe")
            if not os.path.exists(self.path_to_undark):
                raise IngestModuleException("EXE was not found in module folder")                   
        

        # Settings attributes
        self.att_dp_type = self.create_attribute_type('YPA_DP_TYPE', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Type", skCase)
        self.att_dp_offset = self.create_attribute_type('YPA_DP_OFFSET', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Offset", skCase)
        self.att_dp_lenght = self.create_attribute_type('YPA_DP_LENGHT', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Lenght", skCase)
        self.att_dp_data = self.create_attribute_type('YPA_DP_DATA', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Data", skCase)
        
        # Address attributes
        self.att_contact_id = self.create_attribute_type('YPA_CONTACT_ID', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Contact id", skCase)
        self.att_address = self.create_attribute_type('YPA_ADDRESS', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Address", skCase)
        self.att_display_name = self.create_attribute_type('YPA_DISPLAY_NAME', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Display name", skCase)
        self.att_address_type = self.create_attribute_type('YPA_ADDRESS_TYPE', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Address type", skCase)
        self.att_times_contacted = self.create_attribute_type('YPA_TIMES_CONTACTED', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Times contacted", skCase)
        self.att_last_contacted_time = self.create_attribute_type('YPA_LAST_CONTACT_TIME', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Last contacted time", skCase) 
        
        # Last updated time
        self.att_last_updated_time = self.create_attribute_type('YPA_LAST_UPDATE_TIME', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Last updated time", skCase) 

        # Conversations attributes
        self.att_thread_id = self.create_attribute_type('YPA_THREAD_ID', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Thread id", skCase) 
        self.att_message_id = self.create_attribute_type('YPA_MESSAGE_ID', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Message id", skCase) 
        self.att_recipient_list = self.create_attribute_type('YPA_RECIPIENT_LIST', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Recipients", skCase) 
        self.att_from_address = self.create_attribute_type('YPA_FROM_ADDRESS', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING , "Address", skCase) 
        self.att_body = self.create_attribute_type('YPA_BODY', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Message Body", skCase) 
        self.att_status = self.create_attribute_type('YPA_STATUS', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Status", skCase)         
        self.att_timestamp = self.create_attribute_type('YPA_TIMESTAMP', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Timestamp", skCase)      

        # MMS-related attributes
        self.att_mms_text = self.create_attribute_type('YPA_MMS_TEXT', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Text", skCase)
        self.att_num_of_files = self.create_attribute_type('YPA_NUM_OF_FILES', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Number of files", skCase)
        self.att_name_of_files = self.create_attribute_type('YPA_NAME_OF_FILES', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Name of files", skCase)
     
        # Picture size (B)
        self.att_pic_size = self.create_attribute_type('YPA_PIC_SIZE', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.LONG, "Picture size (B)", skCase)

        # DB User Version
        self.att_db_uv = self.create_attribute_type('YPA_DB_UV', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Sqlite User Version", skCase)

        # Recovered rows
        self.att_rec_row = self.create_attribute_type('YPA_REC_ROW', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Data recovered from unvacuumed row", skCase)
        
        # photo.db photo attributes
        self.att_photo_id = self.create_attribute_type('YPA_PHOTO_ID', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Photo id", skCase)
        self.att_uri = self.create_attribute_type('YPA_URI', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "URI", skCase)
        self.att_photo_thumbnail = self.create_attribute_type('YPA_PHOTO_THUMBNAIL', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.BYTE, "Thumbnail", skCase)
        self.att_photo = self.create_attribute_type('YPA_PHOTO_FULL', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.BYTE, "Blob", skCase)

        # DB queries
        self.contact_query = "select a.contact_id, a.address,c.display_name, a.address_type, a.times_contacted, datetime(a.last_contacted_time / 10000000 - 11644473600,'unixepoch') as last_contacted_time,  datetime(c.last_updated_time/ 10000000 - 11644473600,'unixepoch') as last_updated_time from address a join contact c on a.contact_id = c.contact_id"
        self.messages_query = "select m.thread_id, m.message_id, con.recipient_list , ifnull(c.display_name,'n/a') as display_name,  m.body, m.status, ifnull(m.from_address,'self') as from_address, datetime(m.timestamp/ 10000000 - 11644473600,'unixepoch') as timestamp from message m left join address a on m.from_address = a.address left join contact c on a.contact_id = c.contact_id join conversation con on con.thread_id = m.thread_id order by m.message_id"
        self.mms_query = "select mp.message_id, mm.thread_id, mp.content_type, mp.name, mp.text, ifnull(c.display_name,'n/a') as display_name, ma.address from mms_part mp left join mms mm on mp.message_id = mm.message_id left join mms_address ma on mp.message_id = ma.message_id left join address a on ma.address = a.address left join contact c on a.contact_id = c.contact_id where ma.address not like 'insert-address-token' "
        self.address_types = {'1' : 'Home phone number' , '2' : 'Mobile phone number' , '3' : 'Office phone number' , '4' : 'Unknown' , '5' : 'Main phone number' , '6' : 'Other phone number'}
        self.photos_query = "select photo_id, name, datetime(last_updated_time/ 10000000 - 11644473600,'unixepoch') as last_updated_time, size, uri, thumbnail, blob from photo" 
        
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
        self.anyValidFileFound = False
        for file in files:
            dbConn, dbPath = self.create_db_conn(file)
            try:
                full_path = (file.getParentPath() + file.getName()) 
                split = full_path.split('/')                  
                try:
                    try:
                        userName = split[-11]
                    except IndexError:
                        userName = "UNKNOWN"
                    self.art_contacts = self.create_artifact_type("YPA_CONTACTS_"+ userName,"User " + userName+ " - Contacts", skCase)
                    self.art_messages = self.create_artifact_type("YPA_MESSAGE_"+ userName,"User " + userName+ " - SMS", skCase)
                    self.art_mms = self.create_artifact_type("YPA_MMS_"+ userName,"User " + userName+ " - MMS", skCase)
                    self.art_pictures = self.create_artifact_type("YPA_PICTURES_"+ userName,"User " + userName+  " - Recent Pictures", skCase)
                    self.art_freespace = self.create_artifact_type("YPA_FREESPACE_"+ userName,"User " + userName+  " - Rows Recovered(undark)", skCase)
                    self.art_dp = self.create_artifact_type("YPA_DP_"+ userName,"User " + userName+ " - Rows Recovered(Delete parser)", skCase)
                    self.art_settings = self.create_artifact_type("YPA_SETTINGS_"+ userName,"User " + userName+ " - Database Settings", skCase)
                    self.art_photo = self.create_artifact_type("YPA_PHOTO_"+ userName, "User " + userName+ " - Photos", skCase)
                except Exception as e:
                    self.log(Level.INFO, str(e))
                    continue

                self.processContacts(self.execute_query(self.contact_query, dbConn),file,blackboard,skCase)

                self.processMessages(self.execute_query(self.messages_query, dbConn),file,blackboard,skCase)
                
                self.processMms(self.execute_query(self.mms_query, dbConn),file,blackboard,skCase)
                
                self.anyValidFileFound = True

                prag_uv = self.execute_query("pragma user_version", dbConn)

                art = file.newArtifact(self.art_settings.getTypeID())
                prag_uv.next()
                art.addAttribute(BlackboardAttribute(self.att_db_uv, YourPhoneIngestModuleFactory.moduleName, prag_uv.getString("user_version")))
                self.index_artifact(blackboard, art,self.art_settings)

                # Other YP databases (photos.db, notifications.db, settings.db)
                dbs = fileManager.findFiles(dataSource, "%.db", file.getParentPath())
                # dbs = [item for item in dbs if "phone.db" not in item.getName()]
                for db in dbs:
                    db_name = db.getName()
                    if "phone.db" in db_name:
                        continue
                    if "notifications.db" in db_name:
                        # self.process_notifications(db)
                        continue
                    if "settings.db" in db_name:
                        # self.process_settings(db)
                        continue
                    if "photos.db" in db_name:
                        self.process_photos(db, blackboard, skCase)
                        continue
                
                # self.log(Level.INFO, "Number of dbs: " + str(len(dbs)))
                # Undark and mdg
                if PlatformUtil.isWindowsOS():                
                    try:
                        with open(self.temp_dir+'\\freespace.txt','w') as f:
                            subprocess.Popen([self.path_to_undark,'-i', dbPath, '--freespace'],stdout=f).communicate()
                        with open(self.temp_dir+'\\freespace.txt','r') as f:
                            # self.log(Level.INFO, ' '.join([self.path_to_undark,'-i', dbPath, '--freespace >']))
                            # self.log(Level.INFO, "Called undark")
                            line = f.readline()
                            while line:
                                # self.log(Level.INFO, "opened result")
                                art = file.newArtifact(self.art_freespace.getTypeID())
                                art.addAttribute(BlackboardAttribute(self.att_rec_row, YourPhoneIngestModuleFactory.moduleName, str(line)))
                                self.index_artifact(blackboard, art,self.art_freespace)
                                line = f.readline()
                    except Exception as e:
                        self.log(Level.SEVERE, str(e))
                        pass
                try:
                    mdg = mdgMod.mdg_modified.sqlite_rec(dbPath)
                    res = mdg.extract_deleted()
                    for line in res:
                        art = file.newArtifact(self.art_dp.getTypeID())
                        art.addAttribute(BlackboardAttribute(self.att_dp_type, YourPhoneIngestModuleFactory.moduleName, str(line[0])))
                        art.addAttribute(BlackboardAttribute(self.att_dp_offset, YourPhoneIngestModuleFactory.moduleName, str(line[1])))
                        art.addAttribute(BlackboardAttribute(self.att_dp_lenght, YourPhoneIngestModuleFactory.moduleName, str(line[2])))
                        art.addAttribute(BlackboardAttribute(self.att_dp_data, YourPhoneIngestModuleFactory.moduleName, str(line[3])))
                        self.index_artifact(blackboard, art,self.art_dp)                 
                except Exception as e:
                        self.log(Level.SEVERE, str(e))
                        pass
            except Exception as e:
                self.log(Level.SEVERE, str(e))
                continue
            finally:
                # Close existing DB connections and remove temp DBs
                self.close_db_conn(dbConn, dbPath)
            
            # Recent photos (Not the photos in photos.db)
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
                self.log(Level.SEVERE, "Failed to obtain Recent photos")
                continue
        if not self.anyValidFileFound:
            Message.info("YPA: No valid database file found")
            
        return IngestModule.ProcessResult.OK   

    def processMms(self, mms, file, blackboard, skCase):
        if not mms:
            return None
        try:
            mms_obj = {}
            while mms.next():
                mms_id = mms.getString('message_id')
                if mms_id not in mms_obj:
                    mms_obj[mms_id] =[]             
                    mms_obj[mms_id].append(mms.getString('message_id'))    # m~_id        
                    mms_obj[mms_id].append(mms.getString('thread_id'))    # thread_id
                    mms_obj[mms_id].append(mms.getString('display_name'))        # disp_name
                    mms_obj[mms_id].append(mms.getString('address'))            # address
                    mms_obj[mms_id].append('')            # text
                    mms_obj[mms_id].append(0)         # n of multimedia
                    mms_obj[mms_id].append([])            # names of the multimedia files
                if mms.getString('content_type') not in ['text/plain','application/smil']:
                
                    mms_obj[mms_id][5] = mms_obj[mms_id][5] + 1
                    name = mms.getString('name')
                    if  mms.getString('name') == '':
                        name = 'n/a'
                    mms_obj[mms_id][6].append(name)
                if mms.getString('content_type') == 'text/plain':
                    try:                  
                        name = mms.getString('text')

                        if  mms.getString('text') == '':
                            name = 'n/a'
                        mms_obj[mms_id][4] = str(name)

                    except Exception as e:
                        pass         
            for obj in mms_obj:   
                mms_obj[obj][6] = ', '.join(mms_obj[obj][6])
                mms_obj[obj][4] = 'n/a' if mms_obj[obj][4] == '' else mms_obj[obj][4]      
                mms_obj[obj][1] = 'n/a' if mms_obj[obj][1] is None  else mms_obj[obj][1]
                

                art = file.newArtifact(self.art_mms.getTypeID())
                art.addAttribute(BlackboardAttribute(self.att_message_id, YourPhoneIngestModuleFactory.moduleName, mms_obj[obj][0]))
                art.addAttribute(BlackboardAttribute(self.att_thread_id, YourPhoneIngestModuleFactory.moduleName, mms_obj[obj][1]))
                art.addAttribute(BlackboardAttribute(self.att_display_name, YourPhoneIngestModuleFactory.moduleName, mms_obj[obj][2]))
                art.addAttribute(BlackboardAttribute(self.att_address, YourPhoneIngestModuleFactory.moduleName, mms_obj[obj][3]))
                art.addAttribute(BlackboardAttribute(self.att_mms_text, YourPhoneIngestModuleFactory.moduleName, mms_obj[obj][4]))
                art.addAttribute(BlackboardAttribute(self.att_num_of_files, YourPhoneIngestModuleFactory.moduleName, str(mms_obj[obj][5])))
                art.addAttribute(BlackboardAttribute(self.att_name_of_files, YourPhoneIngestModuleFactory.moduleName, mms_obj[obj][6]))                
                self.index_artifact(blackboard, art,self.art_mms)
        except Exception as e:
            self.log(Level.SEVERE, str(e))
            return None

    def processMessages(self, messages, file, blackboard, skCase):
        if not messages:
            return None
        try:
            while messages.next():
                art = file.newArtifact(self.art_messages.getTypeID())
                art.addAttribute(BlackboardAttribute(self.att_thread_id, YourPhoneIngestModuleFactory.moduleName, messages.getString('thread_id')))
                art.addAttribute(BlackboardAttribute(self.att_message_id, YourPhoneIngestModuleFactory.moduleName, messages.getString('message_id')))
                art.addAttribute(BlackboardAttribute(self.att_recipient_list, YourPhoneIngestModuleFactory.moduleName, messages.getString('recipient_list')))
                art.addAttribute(BlackboardAttribute(self.att_from_address, YourPhoneIngestModuleFactory.moduleName, messages.getString('from_address')))
                art.addAttribute(BlackboardAttribute(self.att_display_name, YourPhoneIngestModuleFactory.moduleName, messages.getString('display_name')))
                art.addAttribute(BlackboardAttribute(self.att_body, YourPhoneIngestModuleFactory.moduleName, messages.getString('body')))
                art.addAttribute(BlackboardAttribute(self.att_status, YourPhoneIngestModuleFactory.moduleName, "Read" if messages.getString('status') == '2' else 'Unread' ))
                art.addAttribute(BlackboardAttribute(self.att_timestamp, YourPhoneIngestModuleFactory.moduleName, messages.getString('timestamp')))
                self.index_artifact(blackboard, art,self.art_messages)
        except Exception as e:
            self.log(Level.SEVERE, str(e))
            return None
                
    def processContacts(self, contacts, file, blackboard, skCase):
        if not contacts:
            return None
        try:
            while contacts.next():
                art = file.newArtifact(self.art_contacts.getTypeID())
                art.addAttribute(BlackboardAttribute(self.att_contact_id, YourPhoneIngestModuleFactory.moduleName, contacts.getString('contact_id')))
                art.addAttribute(BlackboardAttribute(self.att_address, YourPhoneIngestModuleFactory.moduleName, contacts.getString('address')))
                art.addAttribute(BlackboardAttribute(self.att_display_name, YourPhoneIngestModuleFactory.moduleName, contacts.getString('display_name')))
                art.addAttribute(BlackboardAttribute(self.att_address_type, YourPhoneIngestModuleFactory.moduleName, self.address_types[contacts.getString('address_type')]))
                art.addAttribute(BlackboardAttribute(self.att_times_contacted, YourPhoneIngestModuleFactory.moduleName, contacts.getString('times_contacted')))
                art.addAttribute(BlackboardAttribute(self.att_last_contacted_time, YourPhoneIngestModuleFactory.moduleName, contacts.getString('last_contacted_time')))
                art.addAttribute(BlackboardAttribute(self.att_last_updated_time, YourPhoneIngestModuleFactory.moduleName, contacts.getString('last_updated_time')))
                self.index_artifact(blackboard, art,self.art_contacts)
        except Exception as e:
            self.log(Level.SEVERE, str(e))
            return None


    def process_photos(self, db, blackboard, skCase):
        db_conn, db_path = self.create_db_conn(db)

        photos = self.execute_query(self.photos_query, db_conn)
        if not photos:
            return
        
        try:
            while photos.next():
                art = db.newArtifact(self.art_photo.getTypeID())
                art.addAttribute(BlackboardAttribute(self.att_photo_id, YourPhoneIngestModuleFactory.moduleName, photos.getString('photo_id')))
                art.addAttribute(BlackboardAttribute(self.att_display_name, YourPhoneIngestModuleFactory.moduleName, photos.getString('name')))
                art.addAttribute(BlackboardAttribute(self.att_last_updated_time, YourPhoneIngestModuleFactory.moduleName, photos.getString('last_updated_time')))
                art.addAttribute(BlackboardAttribute(self.att_pic_size, YourPhoneIngestModuleFactory.moduleName, photos.getLong('size')))
                art.addAttribute(BlackboardAttribute(self.att_uri, YourPhoneIngestModuleFactory.moduleName, photos.getString('uri')))
                # blob_bytes = photos.getBytes('thumbnail')
                # art.addAttribute(BlackboardAttribute(self.att_photo_thumbnail, YourPhoneIngestModuleFactory.moduleName, blob_bytes))
                # blob_bytes = photos.getBytes('blob')
                # art.addAttribute(BlackboardAttribute(self.att_photo, YourPhoneIngestModuleFactory.moduleName, blob_bytes))
                self.index_artifact(blackboard, art, self.art_photo)
        except Exception as e:
            self.log(Level.SEVERE, str(e))
            return None

        self.close_db_conn(db_conn, db_path)

class YourPhoneWithUISettings(IngestModuleIngestJobSettings): # These are just in case we end up needing an UI
    serialVersionUID = 1L
    
    def __init__(self):
        self.flag = False
        self.flag1 = False
        self.flag2 = False

    def getVersionNumber(self):
        return serialVersionUID

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
    def __init__(self, settings):
        self.local_settings = settings
        self.initComponents()

    def initComponents(self):
        self.setLayout(BoxLayout(self, BoxLayout.Y_AXIS))
        # self.setLayout(GridLayout(0,1))
        self.setAlignmentX(JComponent.LEFT_ALIGNMENT)
        self.panel1 = JPanel()
        self.panel1.setLayout(BoxLayout(self.panel1, BoxLayout.Y_AXIS))
        self.panel1.setAlignmentY(JComponent.LEFT_ALIGNMENT)
        self.add(self.panel1)

    # Return the settings used
    def getSettings(self):
        return self.local_settings