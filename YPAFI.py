import jarray
import inspect
import os
import subprocess
import time
import json
import sys
import csv
import mdgMod
import json

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
from java.lang import Class, System, IllegalArgumentException
from java.sql import DriverManager, SQLException
from java.util.logging import Level
from java.io import File
from org.sleuthkit.datamodel import SleuthkitCase
from org.sleuthkit.datamodel import AbstractFile
from org.sleuthkit.datamodel import TskCoreException
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
from org.sleuthkit.autopsy.ingest import GenericIngestModuleJobSettings

from org.sleuthkit.datamodel import CommunicationsManager
from org.sleuthkit.datamodel import Relationship
from org.sleuthkit.datamodel import Account

from db import db_functions
from crawler import wal_crawler

# DB queries
CONTACT_QUERY = "select a.contact_id, a.address,c.display_name, a.address_type, a.times_contacted, (a.last_contacted_time / 10000000 - 11644473600) as last_contacted_time,  (c.last_updated_time/ 10000000 - 11644473600) as last_updated_time from address a join contact c on a.contact_id = c.contact_id"
MESSAGES_QUERY = "select m.thread_id, m.message_id, con.recipient_list , ifnull(c.display_name,'n/a') as display_name,  m.body, m.status, CASE WHEN ifnull(m.from_address,'Self') = '' THEN 'Self' ELSE ifnull(m.from_address,'Self') END as from_address,(m.timestamp / 10000000 - 11644473600) as timestamp from message m left join address a on m.from_address = a.address left join contact c on a.contact_id = c.contact_id join conversation con on con.thread_id = m.thread_id order by m.message_id"
MMS_QUERY = "select mp.message_id, mm.thread_id, mp.content_type, mp.name, mp.text, ifnull(c.display_name,'n/a') as display_name, ma.address from mms_part mp left join mms mm on mp.message_id = mm.message_id left join mms_address ma on mp.message_id = ma.message_id left join address a on ma.address = a.address left join contact c on a.contact_id = c.contact_id where ma.address not like 'insert-address-token' "
ADDRESS_TYPE = {'1' : 'Home phone number' , '2' : 'Mobile phone number' , '3' : 'Office phone number' , '4' : 'Unknown' , '5' : 'Main phone number' , '6' : 'Other phone number'}
PHOTOS_QUERY = "select photo_id, name, (last_updated_time/ 10000000 - 11644473600) as last_updated_time, size, uri, thumbnail, blob from photo" 
PHOTOS_MEDIA_QUERY = "SELECT m.id, IFNULL(p.photo_id, 'N/A') as photo_id, m.name, (m.last_updated_time / 10000000 - 11644473600) as last_updated_time, \
    (m.taken_time / 10000000 - 11644473600) as taken_time, m.size, IFNULL(p.uri, m.uri) as uri, IFNULL(NULLIF(m.orientation, ''), 'N/A') as orientation, \
    (m.last_seen_time / 10000000 - 11644473600) as last_seen_time, height, width \
FROM media m \
LEFT JOIN photo p ON m.name = p.name;"
APPS_QUERY = "select app_name, package_name, version, etag from phone_apps"
SETTINGS_QUERY = "select setting_group_id, setting_key, setting_type, setting_value from settings"
NOTIFICATIONS_QUERY = "select notification_id, json, (post_time/ 10000000 - 11644473600) as post_time, state, anonymous_id from notifications"
CONTACT_QUERY_ATTACHED = "SELECT a.contact_id, c.phone_number AS address , a.display_name, c.phone_number_type AS address_type, \
    (a.last_updated_time/ 10000000 - 11644473600) AS last_updated_time, \
    cd.display_date AS last_contacted_time, 0 AS times_contacted \
FROM contactsDB.contact a \
JOIN contactsDB.phonenumber c ON a.contact_id = c.contact_id \
LEFT JOIN contactsDB.contactdate cd ON a.contact_id = cd.contact_id"
MESSAGES_QUERY_ATTACHED = "SELECT m.thread_id, m.message_id, con.recipient_list, \
    ifnull(c.display_name,'n/a') as display_name, m.body, m.status, \
    CASE WHEN ifnull(m.from_address,'Self') = '' THEN 'Self' ELSE ifnull(m.from_address,'Self') END AS from_address, \
    (m.timestamp / 10000000 - 11644473600) AS timestamp \
FROM message m \
LEFT JOIN (SELECT * FROM phonenumber WHERE contact_id IN (SELECT contact_id FROM contact)) a on m.from_address = a.phone_number \
LEFT JOIN contactsDB.contact c ON a.contact_id = c.contact_id \
JOIN conversation con on con.thread_id = m.thread_id \
GROUP BY m.message_id \
ORDER BY m.message_id;"
MMS_QUERY_ATTACHED = "SELECT mp.message_id, mm.thread_id, mp.content_type, mp.name, mp.text, ifnull(c.display_name,'n/a') as display_name, ma.address \
FROM mms_part mp \
LEFT JOIN mms mm on mp.message_id = mm.message_id \
LEFT JOIN mms_address ma on mp.message_id = ma.message_id \
LEFT JOIN contactsDB.phonenumber a on ma.address = a.phone_number \
LEFT JOIN contact c on a.contact_id = c.contact_id \
WHERE ma.address NOT LIKE 'insert-address-token';"
CALLINGS_QUERY = "SELECT call_id, c.contact_id, c.display_name, ch.phone_number, duration, \
    call_type, (start_time / 10000000 - 11644473600) AS start_time, is_read, \
    (ch.last_updated_time / 10000000 - 11644473600) AS last_updated_time \
FROM call_history ch \
JOIN contactsDB.phonenumber pn ON ch.phone_number = pn.display_phone_number \
JOIN contactsDB.contact c ON pn.contact_id = c.contact_id \
UNION \
SELECT call_id, ifnull(c.contact_id, 'Unknown'), ifnull(c.display_name, 'Unknown'), ch.phone_number, duration, call_type, \
    (start_time / 10000000 - 11644473600) AS start_time, is_read, \
    (ch.last_updated_time / 10000000 - 11644473600) AS last_updated_time \
FROM call_history ch \
LEFT JOIN contactsDB.phonenumber pn ON ch.phone_number = pn.display_phone_number \
LEFT JOIN contactsDB.contact c ON pn.contact_id = c.contact_id \
WHERE pn.display_phone_number IS NULL"

CALL_TYPE = {
    '1' : 'Incoming',
    '2' : 'Outgoing',
    '3' : 'Missed'
}
IS_READ_TYPE = {
    0 : 'Taken',
    1 : 'Missed'
}
# Factory that defines the name and details of the module and allows Autopsy
# to create instances of the modules that will do the analysis.
class YourPhoneIngestModuleFactory(IngestModuleFactoryAdapter):

    def __init__(self):
        self.settings = None

    moduleName = "Windows Your Phone Analyzer"

    def getModuleDisplayName(self):
        return self.moduleName

    def getModuleDescription(self):
        return "Parses and analyzes information regarding Windows 10's Your Phone App"

    def getModuleVersionNumber(self):
        return "0.3"

    def getDefaultIngestJobSettings(self):
        # return YourPhoneWithUISettings()
        return GenericIngestModuleJobSettings()

    def hasIngestJobSettingsPanel(self):
        return True

    def getIngestJobSettingsPanel(self, settings):
        # if not isinstance(settings, YourPhoneWithUISettings):
        #    raise IllegalArgumentException("Expected settings argument to be instanceof YourPhoneWithUISettings")
        # self.settings = settings
        # return YourPhoneWithUISettingsPanel(self.settings)
        if not isinstance(settings, GenericIngestModuleJobSettings):
            settings = GenericIngestModuleJobSettings()
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

    def get_or_create_account(self, manager, file, phone_number):
        return manager.createAccountFileInstance(Account.Type.PHONE, phone_number, YourPhoneIngestModuleFactory.moduleName, file.getDataSource())

    def index_artifact(self, blackboard, artifact, artifact_type):
        try:
            # Index the artifact for keyword search
            blackboard.indexArtifact(artifact)
        except Blackboard.BlackboardException as e:
            self.log(Level.INFO, "Error indexing artifact " +
                     artifact.getDisplayName() + "" +str(e))
        # Fire an event to notify the UI and others that there is a new log artifact
        IngestServices.getInstance().fireModuleDataEvent(
            ModuleDataEvent(YourPhoneIngestModuleFactory.moduleName,
                            artifact_type, None))

    def create_artifact_type(self, art_name, art_desc, blackboard):
        try:
            art = blackboard.getOrAddArtifactType(art_name, "YPA: " + art_desc)
            self.art_list.append(art)
        except Exception as e :
            self.log(Level.INFO, "Error getting or adding artifact type: " + art_desc + " " + str(e))
        return art

    def create_attribute_type(self, att_name, type_name, att_desc, blackboard):
        try:
            att_type = blackboard.getOrAddAttributeType(att_name, type_name, att_desc)
        except Exception as e:
            self.log(Level.INFO, "Error getting or adding attribute type: " + att_desc + " " + str(e))
        return att_type

    # Where any setup and configuration is done
    # 'context' is an instance of org.sleuthkit.autopsy.ingest.IngestJobContext.
    # See: http://sleuthkit.org/autopsy/docs/api-docs/3.1/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_ingest_job_context.html
    def startUp(self, context):
        blackboard = Case.getCurrentCase().getServices().getBlackboard()
        self.temp_dir = Case.getCurrentCase().getTempDirectory()
        if PlatformUtil.isWindowsOS():
            #self.path_to_exe = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ypa.exe") #OLD
            self.path_to_undark = os.path.join(os.path.dirname(os.path.abspath(__file__)), "undark.exe")
            if not os.path.exists(self.path_to_undark):
                raise IngestModuleException("EXE was not found in module folder")                   
        

        # Settings attributes
        self.att_dp_type = self.create_attribute_type('YPA_DP_TYPE', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Type", blackboard)
        self.att_dp_offset = self.create_attribute_type('YPA_DP_OFFSET', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Offset", blackboard)
        self.att_dp_length = self.create_attribute_type('YPA_DP_LENGTH', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Length", blackboard)
        self.att_dp_data = self.create_attribute_type('YPA_DP_DATA', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Data", blackboard)
        
        # Address attributes
        self.att_contact_id = self.create_attribute_type('YPA_CONTACT_ID', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Contact ID", blackboard)
        self.att_address = self.create_attribute_type('YPA_ADDRESS', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Address", blackboard)
        self.att_display_name = self.create_attribute_type('YPA_DISPLAY_NAME', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Display name", blackboard)
        self.att_address_type = self.create_attribute_type('YPA_ADDRESS_TYPE', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Address type", blackboard)
        self.att_times_contacted = self.create_attribute_type('YPA_TIMES_CONTACTED', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Times contacted", blackboard)
        self.att_last_contacted_time = self.create_attribute_type('YPA_LAST_CONTACT_TIME', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME, "Last contacted time", blackboard) 
        
        # Last updated time
        self.att_last_updated_time = self.create_attribute_type('YPA_LAST_UPDATE_TIME', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME, "Last updated time", blackboard) 

        # Conversations attributes
        self.att_thread_id = self.create_attribute_type('YPA_THREAD_ID', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Thread ID", blackboard) 
        self.att_message_id = self.create_attribute_type('YPA_MESSAGE_ID', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Message ID", blackboard) 
        self.att_recipient_list = self.create_attribute_type('YPA_RECIPIENT_LIST', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Recipients", blackboard) 
        self.att_from_address = self.create_attribute_type('YPA_FROM_ADDRESS', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING , "Address", blackboard) 
        self.att_body = self.create_attribute_type('YPA_BODY', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Message body", blackboard) 
        self.att_status = self.create_attribute_type('YPA_STATUS', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Status", blackboard)         
        self.att_timestamp = self.create_attribute_type('YPA_TIMESTAMP', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME, "Timestamp", blackboard)      

        # MMS-related attributes
        self.att_mms_text = self.create_attribute_type('YPA_MMS_TEXT', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Text", blackboard)
        self.att_num_of_files = self.create_attribute_type('YPA_NUM_OF_FILES', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Number of files", blackboard)
        self.att_name_of_files = self.create_attribute_type('YPA_NAME_OF_FILES', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Name of files", blackboard)
     
        # Picture size (B)
        self.att_pic_size = self.create_attribute_type('YPA_PIC_SIZE', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.LONG, "Picture size (B)", blackboard)

        # DB User Version
        self.att_db_uv = self.create_attribute_type('YPA_DB_UV', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "SQLite User Version", blackboard)

        # Recovered rows
        self.att_rec_row = self.create_attribute_type('YPA_REC_ROW', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Data recovered from unvacuumed row", blackboard)
        
        # photo.db photo attributes
        self.att_photo_id = self.create_attribute_type('YPA_PHOTO_ID', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Photo ID", blackboard)
        self.att_uri = self.create_attribute_type('YPA_URI', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "URI", blackboard)
        self.att_media_id = self.create_attribute_type('YPA_MEDIA_ID', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Media ID", blackboard)
        self.att_taken_time = self.create_attribute_type('YPA_TAKEN_TIME', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME, "Taken time", blackboard)
        self.att_orientation = self.create_attribute_type('YPA_ORIENTATION', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Orientation", blackboard)
        self.att_last_seen_time = self.create_attribute_type('YPA_LAST_SEEN_TIME', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME, "Last seen", blackboard)
        self.att_height = self.create_attribute_type('YPA_HEIGHT', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.LONG, "Height", blackboard)
        self.att_width = self.create_attribute_type('YPA_WIDTH', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.LONG, "Width", blackboard)

        # Apps from settings.db
        self.att_package_name = self.create_attribute_type('YPA_APP_PACKAGE_NAME', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Package name", blackboard)
        self.att_version = self.create_attribute_type('YPA_APP_VERSION', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Version", blackboard)
        self.att_app_etag = self.create_attribute_type('YPA_APP_ETAG', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Etag", blackboard)

        # Settings from settings.db
        self.att_setting_group_id = self.create_attribute_type('YPA_SETTING_GROUP_ID', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Setting Group ID", blackboard)
        self.att_setting_key = self.create_attribute_type('YPA_SETTING_KEY', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Setting key", blackboard)
        self.att_setting_type = self.create_attribute_type('YPA_SETTING_TYPE', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Setting type", blackboard)
        self.att_setting_value = self.create_attribute_type('YPA_SETTING_VALUE', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Setting value", blackboard)

        # Notifications from notifications.db
        self.att_post_time = self.create_attribute_type('YPA_POST_TIME', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME, "Post time", blackboard)
        self.att_notification_id = self.create_attribute_type('YPA_NOTIFICATION_ID', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Notification ID", blackboard)
        self.att_anon_id = self.create_attribute_type('YPA_ANON_ID', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Anonymous ID", blackboard)
        self.att_state = self.create_attribute_type('YPA_STATE', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "State", blackboard)
        self.att_full_json = self.create_attribute_type('YPA_FULL_JSON', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Full JSON", blackboard)
        self.att_text = self.create_attribute_type('YPA_TEXT', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Text", blackboard)

        # Call history from calling.db
        self.att_call_id = self.create_attribute_type('YPA_CALL_ID', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Call ID", blackboard)
        self.att_duration = self.create_attribute_type('YPA_CALL_DURATION', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.LONG, "Duration", blackboard)
        self.att_call_type = self.create_attribute_type('YPA_CALL_TYPE', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Call type", blackboard)
        self.att_start_time = self.create_attribute_type('YPA_START_TIME', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME, "Start time", blackboard)
        self.att_is_read = self.create_attribute_type('YPA_IS_READ', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Is read", blackboard)

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
        self.log(Level.INFO, "Found " + str(len(files)) + " files (phone.db)")
        self.valid_files_found = False
        
        for file in files:
            full_path = (file.getParentPath() + file.getName())
            dbConn, dbPath = db_functions.create_db_conn(self, file)
            try:
                split = full_path.split('/')                  
                try:
                    try:
                        username = split[-11]
                        guid = split[-4]
                    except IndexError:
                        username = "UNKNOWN"
                        guid = "UNKNOWN"
                    self.art_contacts = self.create_artifact_type("YPA_CONTACTS_" + guid + "_" + username,"User " + username + " - Contacts", blackboard)
                    self.art_messages = self.create_artifact_type("YPA_MESSAGE_" + guid + "_" + username,"User " + username + " - SMS", blackboard)
                    self.art_mms = self.create_artifact_type("YPA_MMS_" + guid + "_" + username,"User " + username + " - MMS", blackboard)
                    self.art_pictures = self.create_artifact_type("YPA_PICTURES_" + guid + "_" + username,"User " + username +  " - Recent pictures", blackboard)
                    self.art_freespace = self.create_artifact_type("YPA_FREESPACE_" + guid + "_" + username,"User " + username +  " - Rows recovered (undark)", blackboard)
                    self.art_dp = self.create_artifact_type("YPA_DP_" + guid + "_" + username,"User " + username + " - Rows recovered (Delete parser)", blackboard)
                    self.art_settings = self.create_artifact_type("YPA_SETTINGS_" + guid + "_" + username,"User " + username + " - Database settings", blackboard)
                    self.art_photo = self.create_artifact_type("YPA_PHOTO_" + guid + "_" + username, "User " + username + " - Photos", blackboard)
                    self.art_phone_app = self.create_artifact_type("YPA_PHONE_APP_" + guid + "_" + username, "User " + username + " - Phone apps", blackboard)
                    self.art_phone_setting = self.create_artifact_type("YPA_PHONE_SETTING_" + guid + "_" + username, "User " + username + " - Phone settings", blackboard)
                    self.art_phone_notification = self.create_artifact_type("YPA_PHONE_NOTIFICATION_" + guid + "_" + username, "User " + username + " - Notifications", blackboard)
                    self.art_call = self.create_artifact_type("YPA_CALLING_" + guid + "_" + username, "User " + username + " - Call history", blackboard)
                except Exception as e:
                    self.log(Level.INFO, str(e))
                    continue

                self.process_db_user_version(db_functions.execute_query(self, "PRAGMA user_version", dbConn, file.getName()), file, blackboard, skCase)

                self.valid_files_found = True

                # Other YP databases
                dbs = fileManager.findFiles(dataSource, "%.db", file.getParentPath())
                
                wal_files = fileManager.findFiles(dataSource, "%.db-wal", file.getParentPath())
                for wal_file in wal_files:
                    try:
                        self.log(Level.INFO, "Crawling " + wal_file.getName())
                        wal_path = os.path.join(self.temp_dir, str(wal_file.getName()))
                        ContentUtils.writeToFile(wal_file, File(wal_path))
                        wal_crawler.crawl(wal_path, self.temp_dir, wal_file.getName() + '.csv')
                        self.log(Level.INFO, "Successfully crawled for " + wal_file.getName())
                    except Exception as e:
                        self.log(Level.INFO, "Failed to crawl for " + wal_file.getName())
                        self.log(Level.SEVERE, str(e))
                
                # dbs = [item for item in dbs if "phone.db" not in item.getName()]
                # Jython does not support Stream predicates... :'( Ugly code follows
                has_contacts_db = False
                for db in dbs:
                    if "contacts.db" in db.getName():
                        has_contacts_db = True
                        break
                
                if has_contacts_db:
                    # We are in a new DB schema!
                    contact_db_path = os.path.join(file.getLocalPath().rsplit('\\', 1)[0], "contacts.db")
                    attach_query = ("ATTACH DATABASE \"" + contact_db_path + "\" AS contactsDB")
                    dbConn = db_functions.execute_statement(self, attach_query, dbConn, file.getName())
                    self.processContacts(db_functions.execute_query(self, CONTACT_QUERY_ATTACHED, dbConn, file.getName()), file, blackboard, skCase)
                    self.processMessages(db_functions.execute_query(self, MESSAGES_QUERY_ATTACHED, dbConn, file.getName()), file, blackboard, skCase, username)
                    self.processMms(db_functions.execute_query(self, MMS_QUERY_ATTACHED, dbConn, file.getName()), file, blackboard, skCase)

                    for db in dbs:
                        db_name = db.getName()
                        if "notifications.db" in db_name:
                            self.process_notifications(db, blackboard, skCase)
                            continue
                        if "settings.db" in db_name:
                            self.process_settings(db, blackboard, skCase)
                            continue
                        if "photos.db" in db_name:
                            self.process_photos(db, blackboard, skCase)
                            continue
                        if "calling.db" in db_name:
                            self.process_calling(db, blackboard, skCase, attach_query, username)
                            continue
                        if "contacts.db" in db_name:
                            self.process_recovery(contact_db_path, db, blackboard)
                            continue
                else:
                    self.processContacts(db_functions.execute_query(self, CONTACT_QUERY, dbConn, file.getName()), file, blackboard, skCase)
                    self.processMessages(db_functions.execute_query(self, MESSAGES_QUERY, dbConn, file.getName()), file, blackboard, skCase, username)
                    self.processMms(db_functions.execute_query(self, MMS_QUERY, dbConn, file.getName()), file, blackboard, skCase)
                    
                    for db in dbs:
                        db_name = db.getName()
                        if "notifications.db" in db_name:
                            self.process_notifications(db, blackboard, skCase)
                            continue
                        if "settings.db" in db_name:
                            self.process_settings(db, blackboard, skCase)
                            continue
                        if "photos.db" in db_name:
                            self.process_photos(db, blackboard, skCase)
                            continue
                
                # self.log(Level.INFO, "Number of dbs: " + str(len(dbs)))
                # Undark and mdg
                self.process_recovery(dbPath, file, blackboard)
            except Exception as e:
                self.log(Level.SEVERE, str(e))
                continue
            finally:
                # Close existing DB connections and remove temp DBs
                db_functions.close_db_conn(self, dbConn, dbPath)
            
            # Recent photos (Not the photos in photos.db)
            try:
                full_path = (file.getParentPath() + file.getName())
                split = full_path.split('/')
                guidPath = '/'.join(split[:-3])
                usrPath = guidPath+'/User'
                ufiles = fileManager.findFiles(dataSource, '%', usrPath)
                for ufile in ufiles:
                    rpPath = ufile.getParentPath() + ufile.getName() +'/Recent Photos/' 
                    picfiles = fileManager.findFiles(dataSource, '%', rpPath)
                    for pic in picfiles:
                        # Make an artifact
                        art = pic.newArtifact(self.art_pictures.getTypeID())
                        # Register file size
                        art.addAttribute(BlackboardAttribute(self.att_pic_size, YourPhoneIngestModuleFactory.moduleName, pic.getSize()))
                        self.index_artifact(blackboard, art, self.art_pictures)
            except Exception as e:
                self.log(Level.SEVERE, "Failed to obtain Recent photos")
                continue
        
        if not self.valid_files_found:
            Message.info("YPA: No valid database file found")
            
        return IngestModule.ProcessResult.OK   

    def process_db_user_version(self, prag_uv, file, blackboard, skCase):
        art = file.newArtifact(self.art_settings.getTypeID())
        prag_uv.next()
        user_version = prag_uv.getString("user_version")
        art.addAttribute(BlackboardAttribute(self.att_db_uv, YourPhoneIngestModuleFactory.moduleName, user_version))
        self.index_artifact(blackboard, art, self.art_settings)
        return user_version

    def processMms(self, mms, file, blackboard, skCase):
        if not mms:
            return
        try:
            mms_obj = {}
            while mms.next():
                mms_id = mms.getString('message_id')
                if mms_id not in mms_obj:
                    mms_obj[mms_id] =[]             
                    mms_obj[mms_id].append(mms.getString('message_id'))      
                    mms_obj[mms_id].append(mms.getString('thread_id'))
                    mms_obj[mms_id].append(mms.getString('display_name'))
                    mms_obj[mms_id].append(mms.getString('address'))
                    # Text
                    mms_obj[mms_id].append('')
                    # N of multimedia
                    mms_obj[mms_id].append(0)
                    # Names of the multimedia files
                    mms_obj[mms_id].append([])
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
            return

    def processMessages(self, messages, file, blackboard, skCase, username):
        if not messages:
            return
        commManager = skCase.getCommunicationsManager()
        # "0" is a workaround for the username... Seems like strings are invalid inputs for Autopsy...
        self_contact = self.get_or_create_account(commManager, file, "0")
        while messages.next():
            try:
                timestamp = messages.getLong('timestamp')
                recipients = messages.getString('recipient_list')
                from_address = messages.getString('from_address')
                body = messages.getString('body')
                # Create YPA message
                art = file.newArtifact(self.art_messages.getTypeID())
                art.addAttribute(BlackboardAttribute(self.att_thread_id, YourPhoneIngestModuleFactory.moduleName, messages.getString('thread_id')))
                art.addAttribute(BlackboardAttribute(self.att_message_id, YourPhoneIngestModuleFactory.moduleName, messages.getString('message_id')))
                art.addAttribute(BlackboardAttribute(self.att_recipient_list, YourPhoneIngestModuleFactory.moduleName, recipients))
                art.addAttribute(BlackboardAttribute(self.att_from_address, YourPhoneIngestModuleFactory.moduleName, from_address))
                art.addAttribute(BlackboardAttribute(self.att_display_name, YourPhoneIngestModuleFactory.moduleName, messages.getString('display_name')))
                art.addAttribute(BlackboardAttribute(self.att_body, YourPhoneIngestModuleFactory.moduleName, body))
                art.addAttribute(BlackboardAttribute(self.att_status, YourPhoneIngestModuleFactory.moduleName, "Read" if messages.getString('status') == '2' else 'Unread' ))
                art.addAttribute(BlackboardAttribute(self.att_timestamp, YourPhoneIngestModuleFactory.moduleName, timestamp))
                self.index_artifact(blackboard, art, self.art_messages)

                # Create TSK message, for comms relationships
                art = file.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_MESSAGE)

                #if (type.equals("1")) {
                #    art.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DIRECTION, YourPhoneIngestModuleFactory.moduleName, NbBundle.getMessage(this.getClass(), "TextMessageAnalyzer.bbAttribute.incoming")))
                #} else {
                #    art.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DIRECTION, YourPhoneIngestModuleFactory.moduleName, NbBundle.getMessage(this.getClass(), "TextMessageAnalyzer.bbAttribute.outgoing")))
                #}

                try:
                    other_contact = self.get_or_create_account(commManager, file, recipients)

                    art.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PHONE_NUMBER_FROM, YourPhoneIngestModuleFactory.moduleName, from_address))
                    if from_address == "Self":
                        art.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PHONE_NUMBER_TO, \
                            YourPhoneIngestModuleFactory.moduleName, recipients))
                        commManager.addRelationships(self_contact, [other_contact], art, Relationship.Type.MESSAGE, timestamp)
                        # self.log(Level.INFO, "INFO HERE: FROM (SELF!) " + from_address + " TO " + recipients)
                    else:
                        art.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PHONE_NUMBER_TO, \
                            YourPhoneIngestModuleFactory.moduleName, "Self (" + username + ")"))
                        commManager.addRelationships(other_contact, [self_contact], art, Relationship.Type.MESSAGE, timestamp)
                        # self.log(Level.INFO, "INFO HERE: FROM " + from_address + " TO SELF" )
                    # art.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DIRECTION, YourPhoneIngestModuleFactory.moduleName, type))
                    art.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME, YourPhoneIngestModuleFactory.moduleName, timestamp))
                    # art.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SUBJECT, YourPhoneIngestModuleFactory.moduleName, subject))
                    art.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_TEXT, YourPhoneIngestModuleFactory.moduleName, body))
                    # art.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_MESSAGE_TYPE, YourPhoneIngestModuleFactory.moduleName, NbBundle.getMessage(this.getClass(), "TextMessageAnalyzer.bbAttribute.smsMessage")))           
                    self.index_artifact(blackboard, art, BlackboardArtifact.ARTIFACT_TYPE.TSK_MESSAGE)
                except TskCoreException as e:
                    self.log(Level.INFO, "Autopsy tagged " + recipients + " as an invalid phone number.")

            except Exception as e:
                self.log(Level.SEVERE, str(e))
                
    def processContacts(self, contacts, file, blackboard, skCase):
        if not contacts:
            return
        commManager = skCase.getCommunicationsManager()
        while contacts.next():
            try:
                art = file.newArtifact(self.art_contacts.getTypeID())
                address = contacts.getString('address')
                art.addAttribute(BlackboardAttribute(self.att_contact_id, YourPhoneIngestModuleFactory.moduleName, contacts.getString('contact_id')))
                art.addAttribute(BlackboardAttribute(self.att_address, YourPhoneIngestModuleFactory.moduleName, address))
                art.addAttribute(BlackboardAttribute(self.att_display_name, YourPhoneIngestModuleFactory.moduleName, contacts.getString('display_name')))
                art.addAttribute(BlackboardAttribute(self.att_address_type, YourPhoneIngestModuleFactory.moduleName, ADDRESS_TYPE[contacts.getString('address_type')]))
                art.addAttribute(BlackboardAttribute(self.att_times_contacted, YourPhoneIngestModuleFactory.moduleName, contacts.getString('times_contacted')))
                art.addAttribute(BlackboardAttribute(self.att_last_contacted_time, YourPhoneIngestModuleFactory.moduleName, contacts.getLong('last_contacted_time')))
                art.addAttribute(BlackboardAttribute(self.att_last_updated_time, YourPhoneIngestModuleFactory.moduleName, contacts.getLong('last_updated_time')))
            
                # Add contact SK account
                self.get_or_create_account(commManager, file, address)
                # self.log(Level.INFO, "[" + guid + "] with address " + address)

                self.index_artifact(blackboard, art,self.art_contacts)
            except Exception as e:
                self.log(Level.SEVERE, str(e))

    def process_photos(self, db, blackboard, skCase):
        db_conn, db_path = db_functions.create_db_conn(self, db)
        self.process_recovery(db_path, db, blackboard)

        self.process_db_user_version(db_functions.execute_query(self, "PRAGMA user_version", db_conn, db_path), db, blackboard, skCase)
        
        # Try to make the new query - in case we fail, fallback to the old one
        try:
            photos = db_functions.execute_query(self, PHOTOS_MEDIA_QUERY, db_conn, db.getName())
            new_query = True
        except Exception as e:
            photos = db_functions.execute_query(self, PHOTOS_QUERY, db_conn, db.getName())
            new_query = False
            self.log(Level.INFO, "Failed to use the new media query: " + str(e))
        if not photos:
            return
        
        while photos.next():
            try:
                art = db.newArtifact(self.art_photo.getTypeID())
                art.addAttribute(BlackboardAttribute(self.att_photo_id, YourPhoneIngestModuleFactory.moduleName, photos.getString('photo_id')))
                art.addAttribute(BlackboardAttribute(self.att_display_name, YourPhoneIngestModuleFactory.moduleName, photos.getString('name')))
                art.addAttribute(BlackboardAttribute(self.att_last_updated_time, YourPhoneIngestModuleFactory.moduleName, photos.getLong('last_updated_time')))
                art.addAttribute(BlackboardAttribute(self.att_pic_size, YourPhoneIngestModuleFactory.moduleName, photos.getLong('size')))
                art.addAttribute(BlackboardAttribute(self.att_uri, YourPhoneIngestModuleFactory.moduleName, photos.getString('uri')))
                if new_query:
                    # New query only adds more attributes
                    art.addAttribute(BlackboardAttribute(self.att_media_id, YourPhoneIngestModuleFactory.moduleName, photos.getString('id')))
                    art.addAttribute(BlackboardAttribute(self.att_taken_time, YourPhoneIngestModuleFactory.moduleName, photos.getLong('taken_time')))
                    art.addAttribute(BlackboardAttribute(self.att_orientation, YourPhoneIngestModuleFactory.moduleName, photos.getString('orientation')))
                    art.addAttribute(BlackboardAttribute(self.att_last_seen_time, YourPhoneIngestModuleFactory.moduleName, photos.getLong('last_seen_time')))
                    art.addAttribute(BlackboardAttribute(self.att_width, YourPhoneIngestModuleFactory.moduleName, photos.getLong('width')))
                    art.addAttribute(BlackboardAttribute(self.att_height, YourPhoneIngestModuleFactory.moduleName, photos.getLong('height')))

                self.index_artifact(blackboard, art, self.art_photo)
            except Exception as e:
                self.log(Level.SEVERE, str(e))

        db_functions.close_db_conn(self, db_conn, db_path)

    def process_settings(self, db, blackboard, skCase):
        db_conn, db_path = db_functions.create_db_conn(self, db)
        self.process_recovery(db_path, db, blackboard)

        self.process_db_user_version(db_functions.execute_query(self, "PRAGMA user_version", db_conn, db_path), db, blackboard, skCase)
        apps = db_functions.execute_query(self, APPS_QUERY, db_conn, db.getName())
        if apps:
            while apps.next():
                try:
                    art = db.newArtifact(self.art_phone_app.getTypeID())
                    art.addAttribute(BlackboardAttribute(self.att_display_name, YourPhoneIngestModuleFactory.moduleName, apps.getString('app_name')))
                    art.addAttribute(BlackboardAttribute(self.att_package_name, YourPhoneIngestModuleFactory.moduleName, apps.getString('package_name')))
                    art.addAttribute(BlackboardAttribute(self.att_version, YourPhoneIngestModuleFactory.moduleName, apps.getString('version')))
                    art.addAttribute(BlackboardAttribute(self.att_app_etag, YourPhoneIngestModuleFactory.moduleName, apps.getString('etag')))
                    self.index_artifact(blackboard, art, self.art_phone_app)
                except Exception as e:
                    self.log(Level.SEVERE, str(e))

        apps.close()

        settings = db_functions.execute_query(self, SETTINGS_QUERY, db_conn, db.getName())

        if settings:
            while settings.next():
                try:
                    art = db.newArtifact(self.art_phone_setting.getTypeID())
                    art.addAttribute(BlackboardAttribute(self.att_setting_group_id, YourPhoneIngestModuleFactory.moduleName, settings.getString('setting_group_id')))
                    art.addAttribute(BlackboardAttribute(self.att_setting_key, YourPhoneIngestModuleFactory.moduleName, settings.getString('setting_key')))
                    art.addAttribute(BlackboardAttribute(self.att_setting_type, YourPhoneIngestModuleFactory.moduleName, settings.getString('setting_type')))
                    art.addAttribute(BlackboardAttribute(self.att_setting_value, YourPhoneIngestModuleFactory.moduleName, settings.getString('setting_value')))
                    self.index_artifact(blackboard, art, self.art_phone_setting)
                except Exception as e:
                    self.log(Level.SEVERE, str(e))

        db_functions.close_db_conn(self, db_conn, db_path)

    def process_notifications(self, db, blackboard, skCase):
        db_conn, db_path = db_functions.create_db_conn(self, db)
        self.process_recovery(db_path, db, blackboard)

        self.process_db_user_version(db_functions.execute_query(self, "PRAGMA user_version", db_conn, db_path), db, blackboard, skCase)
        notifications = db_functions.execute_query(self, NOTIFICATIONS_QUERY, db_conn, db.getName())
        
        if not notifications:
            return
        
        while notifications.next():
            try:
                art = db.newArtifact(self.art_phone_notification.getTypeID())
                notific = Notification(notifications.getString('json'))
                art.addAttribute(BlackboardAttribute(self.att_notification_id, YourPhoneIngestModuleFactory.moduleName, notifications.getString('notification_id')))
                art.addAttribute(BlackboardAttribute(self.att_post_time, YourPhoneIngestModuleFactory.moduleName, notifications.getLong('post_time')))
                art.addAttribute(BlackboardAttribute(self.att_display_name, YourPhoneIngestModuleFactory.moduleName, notific.appName))
                art.addAttribute(BlackboardAttribute(self.att_package_name, YourPhoneIngestModuleFactory.moduleName, notific.packageName))
                art.addAttribute(BlackboardAttribute(self.att_timestamp, YourPhoneIngestModuleFactory.moduleName, notific.timestamp / 1000))
                art.addAttribute(BlackboardAttribute(self.att_text, YourPhoneIngestModuleFactory.moduleName, notific.text))
                art.addAttribute(BlackboardAttribute(self.att_full_json, YourPhoneIngestModuleFactory.moduleName, notific.full_json))
                art.addAttribute(BlackboardAttribute(self.att_state, YourPhoneIngestModuleFactory.moduleName, notifications.getString('state')))
                art.addAttribute(BlackboardAttribute(self.att_anon_id, YourPhoneIngestModuleFactory.moduleName, notifications.getString('anonymous_id')))
                self.index_artifact(blackboard, art, self.art_phone_notification)
            except Exception as e:
                self.log(Level.SEVERE, str(e))
        
        db_functions.close_db_conn(self, db_conn, db_path)
    
    def process_calling(self, db, blackboard, skCase, attach_query, username):
        db_conn, db_path = db_functions.create_db_conn(self, db)
        self.process_recovery(db_path, db, blackboard)

        self.process_db_user_version(db_functions.execute_query(self, "PRAGMA user_version", db_conn, db_path), db, blackboard, skCase)
        
        # Attach contacts.db
        db_functions.execute_statement(self, attach_query, db_conn, db.getName())

        call_history = db_functions.execute_query(self, CALLINGS_QUERY, db_conn, db.getName())
        
        commManager = skCase.getCommunicationsManager()
        # "0" is a workaround for the username... Seems like strings are invalid inputs for Autopsy...
        self_contact = self.get_or_create_account(commManager, db, "0")

        if not call_history:
            return
        
        while call_history.next():
            try:
                address = call_history.getString('phone_number')
                start_time = call_history.getLong('start_time')
                art = db.newArtifact(self.art_call.getTypeID())
                art.addAttribute(BlackboardAttribute(self.att_call_id, YourPhoneIngestModuleFactory.moduleName, call_history.getString('call_id')))
                art.addAttribute(BlackboardAttribute(self.att_display_name, YourPhoneIngestModuleFactory.moduleName, call_history.getString('display_name')))
                art.addAttribute(BlackboardAttribute(self.att_address, YourPhoneIngestModuleFactory.moduleName, address))
                art.addAttribute(BlackboardAttribute(self.att_duration, YourPhoneIngestModuleFactory.moduleName, call_history.getLong('duration')))
                art.addAttribute(BlackboardAttribute(self.att_call_type, YourPhoneIngestModuleFactory.moduleName, CALL_TYPE[call_history.getString('call_type')]))
                art.addAttribute(BlackboardAttribute(self.att_start_time, YourPhoneIngestModuleFactory.moduleName, start_time))
                art.addAttribute(BlackboardAttribute(self.att_last_updated_time, YourPhoneIngestModuleFactory.moduleName, call_history.getLong('last_updated_time')))
                is_read = IS_READ_TYPE[call_history.getInt("is_read")]
                art.addAttribute(BlackboardAttribute(self.att_is_read, YourPhoneIngestModuleFactory.moduleName, is_read))
                self.index_artifact(blackboard, art, self.art_call)
                
                # Create TSK call, for comms relationships
                art = db.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_CALLLOG)
                art.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PHONE_NUMBER_FROM, YourPhoneIngestModuleFactory.moduleName, address))
                art.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME_START, YourPhoneIngestModuleFactory.moduleName, start_time))
                other_contact = self.get_or_create_account(commManager, db, address)
                commManager.addRelationships(self_contact, [other_contact], art, Relationship.Type.CALL_LOG, start_time)
                self.index_artifact(blackboard, art, BlackboardArtifact.ARTIFACT_TYPE.TSK_CALLLOG)

            except Exception as e:
                self.log(Level.SEVERE, str(e))
        
        db_functions.close_db_conn(self, db_conn, db_path)

    def process_recovery(self, db_path, file, blackboard):
        self.log(Level.INFO, "Starting recovery...")
        if PlatformUtil.isWindowsOS():                
            try:
                with open(self.temp_dir + '\\freespace.txt','w') as f:
                    subprocess.Popen([self.path_to_undark,'-i', db_path, '--freespace'],stdout=f).communicate()
                with open(self.temp_dir + '\\freespace.txt','r') as f:
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
            mdg = mdgMod.mdg_modified.sqlite_rec(db_path)
            res = mdg.extract_deleted()
            for line in res:
                art = file.newArtifact(self.art_dp.getTypeID())
                art.addAttribute(BlackboardAttribute(self.att_dp_type, YourPhoneIngestModuleFactory.moduleName, str(line[0])))
                art.addAttribute(BlackboardAttribute(self.att_dp_offset, YourPhoneIngestModuleFactory.moduleName, str(line[1])))
                art.addAttribute(BlackboardAttribute(self.att_dp_length, YourPhoneIngestModuleFactory.moduleName, str(line[2])))
                art.addAttribute(BlackboardAttribute(self.att_dp_data, YourPhoneIngestModuleFactory.moduleName, str(line[3])))
                self.index_artifact(blackboard, art,self.art_dp)                 
        except Exception as e:
            self.log(Level.SEVERE, str(e))
            pass

class Notification(object):
    def __init__(self, j):
        self.__dict__ = json.loads(j, encoding='utf-8')
        self.full_json = json.dumps(self.__dict__, indent=4, sort_keys=True, encoding='utf-8')

class YourPhoneWithUISettings(IngestModuleIngestJobSettings): # These are just in case we end up needing an UI
    serialVersionUID = 1L
    
    def __init__(self):
        pass

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