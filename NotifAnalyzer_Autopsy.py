import jarray
import json
import inspect
import subprocess
import os
from java.io import File
from java.lang import System
from java.util.logging import Level
from javax.swing import BoxLayout
from javax.swing import JButton
from javax.swing import JCheckBox
from javax.swing import JLabel
from javax.swing import JPanel
from javax.swing import JComponent
from javax.swing import JTextField
from org.sleuthkit.datamodel import SleuthkitCase
from org.sleuthkit.datamodel import AbstractFile
from org.sleuthkit.datamodel import ReadContentInputStream
from org.sleuthkit.datamodel import BlackboardArtifact
from org.sleuthkit.datamodel import BlackboardAttribute
from org.sleuthkit.autopsy.ingest import IngestModule
from org.sleuthkit.autopsy.ingest.IngestModule import IngestModuleException
from org.sleuthkit.autopsy.ingest import DataSourceIngestModule
from org.sleuthkit.autopsy.ingest import FileIngestModule
from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter
from org.sleuthkit.autopsy.ingest import IngestModuleIngestJobSettings
from org.sleuthkit.autopsy.ingest import IngestModuleIngestJobSettingsPanel
from org.sleuthkit.autopsy.ingest import IngestMessage
from org.sleuthkit.autopsy.ingest import IngestServices
from org.sleuthkit.autopsy.ingest import ModuleDataEvent
from org.sleuthkit.autopsy.ingest import GenericIngestModuleJobSettings
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.coreutils import PlatformUtil
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.casemodule.services import Services
from org.sleuthkit.autopsy.casemodule.services import FileManager
from org.sleuthkit.autopsy.casemodule.services import Blackboard
from org.sleuthkit.autopsy.datamodel import ContentUtils

from crawler import wal_crawler
from bring2lite import main as b2l
import mdgMod

class NotificationAnalyzerDataSourceIngestModuleFactory(IngestModuleFactoryAdapter):

    moduleName = "Windows Notifications Analyzer"

    def getModuleDisplayName(self):
        return self.moduleName

    def getModuleDescription(self):
        return "Parses and analyzes information regarding Windows 10's Notifications"

    def getModuleVersionNumber(self):
        return "0.1"

    def getDefaultIngestJobSettings(self):
        return GenericIngestModuleJobSettings()

    def hasIngestJobSettingsPanel(self):
        return True

    def getIngestJobSettingsPanel(self, settings):
        if not isinstance(settings, GenericIngestModuleJobSettings):
            settings = GenericIngestModuleJobSettings()
        self.settings = settings
        return NotificationAnalyzerWithUISettingsPanel(self.settings)

    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return NotificationAnalyzerDataSourceIngestModule(self.settings)

# Data Source-level ingest module.  One gets created per data source.
class NotificationAnalyzerDataSourceIngestModule(DataSourceIngestModule):

    _logger = Logger.getLogger(NotificationAnalyzerDataSourceIngestModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def __init__(self, settings):
        self.context = None
        self.local_settings = settings

    # Where any setup and configuration is done
    # 'context' is an instance of org.sleuthkit.autopsy.ingest.IngestJobContext.
    # See: http://sleuthkit.org/autopsy/docs/api-docs/latest/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_ingest_job_context.html
    def startUp(self, context):
        self.context = context

        self.temp_dir = Case.getCurrentCase().getTempDirectory()
        blackboard = Case.getCurrentCase().getServices().getBlackboard()
        
        self.use_undark = self.local_settings.getSetting("undark") == "true"
        self.use_mdg = self.local_settings.getSetting("mdg") == "true"
        self.use_crawler = self.local_settings.getSetting("crawler") == "true"
        self.use_b2l = self.local_settings.getSetting("b2l") == "true"
        self.python_path = self.local_settings.getSetting("python_path")
        # TODO: Process recovery
        # TODO: Process handler other assets
        
        # Generic attributes
        self.att_id = self.create_attribute_type('NA_ID', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "ID", blackboard)
        self.att_type = self.create_attribute_type('NA_TYPE', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Type", blackboard)
        self.att_created_time = self.create_attribute_type('NA_CREATED_TIME', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Created time", blackboard)
        self.att_modified_time = self.create_attribute_type('NA_UPDATED_TIME', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Updated time", blackboard)
        self.att_expiry_time = self.create_attribute_type('NA_EXPIRY_TIME', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME, "Expiry time", blackboard)
        self.att_arrival_time = self.create_attribute_type('NA_ARRIVAL_TIME', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME, "Arrival time", blackboard)

        # Notification handler attributes
        self.att_handler_primary_id = self.create_attribute_type('NA_HANDLER_PRIMARY_ID', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Primary ID", blackboard)
        self.att_parent_id = self.create_attribute_type('NA_PARENT_ID', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Parent ID", blackboard)
        self.att_wns_id = self.create_attribute_type('NA_WNS_ID', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "WNS ID", blackboard)
        self.att_wnf_event_name = self.create_attribute_type('NA_WNF_EVENT_NAME', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "WNF Event Name", blackboard)
        self.att_system_data_property_set = self.create_attribute_type('NA_SYSTEM_DATA_PROPERTY_SET', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "System data property set", blackboard)
        self.att_app_name = self.create_attribute_type('NA_APP_NAME', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "App name (Your Phone)", blackboard)

        # Notification attributes
        self.att_payload = self.create_attribute_type('NA_PAYLOAD', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Payload", blackboard)
        self.att_payload_type = self.create_attribute_type('NA_PAYLOAD_TYPE', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Content format", blackboard)
        
        # DB User Version
        self.att_db_uv = self.create_attribute_type('NA_DB_UV', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "SQLite User Version", blackboard)

        # Recovered rows
        self.att_rec_row = self.create_attribute_type('NA_REC_ROW', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Data recovered from unvacuumed row", blackboard)
        
        # Recovery attributes
        self.att_dp_type = self.create_attribute_type('NA_DP_TYPE', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Type", blackboard)
        self.att_dp_offset = self.create_attribute_type('NA_DP_OFFSET', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Offset", blackboard)
        self.att_dp_length = self.create_attribute_type('NA_DP_LENGTH', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Length", blackboard)
        self.att_dp_data = self.create_attribute_type('NA_DP_DATA', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Data", blackboard)

        # WAL crawler attribute
        self.att_list_headers = {}
        for header in wal_crawler.get_headers():
            normalized_header_att_id = header.replace(' ', '_').replace('-', '_')
            self.att_list_headers[header] = self.create_attribute_type('NA_' + normalized_header_att_id, BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, header, blackboard)
        
        # bring2lite attributes
        self.att_b2l_page = self.create_attribute_type('NA_WAL_B2L_PAGE', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Page", blackboard)
        self.att_b2l_row = self.create_attribute_type('NA_WAL_B2L_ROW', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Row content", blackboard)

    # Where the analysis is done.
    # The 'dataSource' object being passed in is of type org.sleuthkit.datamodel.Content.
    # See: http://www.sleuthkit.org/sleuthkit/docs/jni-docs/latest/interfaceorg_1_1sleuthkit_1_1datamodel_1_1_content.html
    # 'progressBar' is of type org.sleuthkit.autopsy.ingest.DataSourceIngestModuleProgress
    # See: http://sleuthkit.org/autopsy/docs/api-docs/latest/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_data_source_ingest_module_progress.html
    def process(self, dataSource, progressBar):

        # we don't know how much work there is yet
        progressBar.switchToIndeterminate()

        blackboard = Case.getCurrentCase().getServices().getBlackboard()
        self.moduleName = NotificationAnalyzerDataSourceIngestModuleFactory.moduleName

        fileManager = Case.getCurrentCase().getServices().getFileManager()
        files = fileManager.findFiles(dataSource, "wpndatabase.db") 

        num_files = len(files)
        self.log(Level.INFO, "Found " + str(num_files) + " Notification databases")
        progressBar.switchToDeterminate(num_files)
        for file in files:
            full_path = (file.getParentPath() + file.getName())
            split = full_path.split('/')
            try:
                username = split[-6]
            except IndexError:
                username = "UNKNOWN"
            self.art_notification = self.create_artifact_type("NA_NOTIFICATION_" + username, "User " + username + " - Notifications", blackboard)
            self.art_notification_handler = self.create_artifact_type("NA_NOTIFICATION_HANDLER_" + username, "User " + username + " - Notification handler", blackboard)
            self.art_settings = self.create_artifact_type("NA_SETTINGS_" + username, "User " + username + " - Database settings", blackboard)

            self.art_wal_crawl = self.create_artifact_type("NA_WAL_CRAWL_" + username, "User " + username + " - WAL Crawled", blackboard)
            self.art_wal_b2l = self.create_artifact_type("NA_WAL_B2L_" + username, "User " + username + " - WAL bring2lite", blackboard)
            self.art_db_schema_b2l = self.create_artifact_type("NA_DB_SCHEMA_B2L_" + username, "User " + username + " - bring2lite DB Schema ", blackboard)
            self.art_db_body_b2l = self.create_artifact_type("NA_DB_BODY_B2L_" + username, "User " + username + " - bring2lite DB Body", blackboard)
            self.art_freespace = self.create_artifact_type("NA_FREESPACE_" + username, "User " + username +  " - Rows recovered (undark)", blackboard)
            self.art_dp = self.create_artifact_type("NA_DP_" + username, "User " + username + " - Rows recovered (Delete parser)", blackboard)

            temp_file = os.path.join(self.temp_dir, file.getName())
            ContentUtils.writeToFile(file, File(temp_file))

            # b2l instance
            b2lite = b2l.main(self.temp_dir)
            b2lite.output = os.path.abspath(self.temp_dir)

            self.db_2lite(b2lite, file, temp_file, blackboard)
            self.process_wal_files(file, fileManager, dataSource, blackboard, b2lite)
            self.process_recovery(temp_file, file, blackboard)

            path_to_script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "NotifAnalyzer.py")
            result_file = os.path.join(self.temp_dir, "result.json")
            self.log(Level.INFO, "Saving notification output to " + str(result_file))
            with open(os.path.join(self.temp_dir, 'na-debug.log'), 'w') as f:
                subprocess.Popen([self.python_path, path_to_script, '-p', temp_file, '-j', result_file],stdout=f).communicate()
            with open(result_file) as json_file:
                data = json.load(json_file)
                
                art = file.newArtifact(self.art_settings.getTypeID())
                user_version = data["user_version"]
                art.addAttribute(BlackboardAttribute(self.att_db_uv, self.moduleName, str(user_version)))
                self.index_artifact(blackboard, art, self.art_settings)
                
                for key, handler in data["assets"].iteritems():
                    for child_key, value in handler.iteritems():
                        if not value and child_key <> "Notifications":
                            handler[child_key] = "N/A"
                    if "AppName" in handler:
                        app_name = handler["AppName"]
                    else:
                        app_name = "N/A"
                    art = file.newArtifact(self.art_notification_handler.getTypeID())
                    art.addAttribute(BlackboardAttribute(self.att_id, self.moduleName, str(handler["HandlerId"])))
                    art.addAttribute(BlackboardAttribute(self.att_handler_primary_id, self.moduleName, str(handler["HandlerPrimaryId"])))
                    art.addAttribute(BlackboardAttribute(self.att_parent_id, self.moduleName, str(handler["ParentId"])))
                    art.addAttribute(BlackboardAttribute(self.att_app_name, self.moduleName, app_name))
                    art.addAttribute(BlackboardAttribute(self.att_created_time, self.moduleName, str(handler["CreatedTime"])))
                    art.addAttribute(BlackboardAttribute(self.att_modified_time, self.moduleName, str(handler["ModifiedTime"])))
                    art.addAttribute(BlackboardAttribute(self.att_wnf_event_name, self.moduleName, str(handler["WNFEventName"])))
                    art.addAttribute(BlackboardAttribute(self.att_type, self.moduleName, str(handler["HandlerType"])))
                    art.addAttribute(BlackboardAttribute(self.att_wns_id, self.moduleName, str(handler["WNSId"])))
                    art.addAttribute(BlackboardAttribute(self.att_system_data_property_set, self.moduleName, str(handler["SystemDataPropertySet"])))
                    self.index_artifact(blackboard, art, self.art_notification_handler)

                    for notification in handler["Notifications"]:
                        art = file.newArtifact(self.art_notification.getTypeID())
                        art.addAttribute(BlackboardAttribute(self.att_type, self.moduleName, str(notification["Type"])))
                        art.addAttribute(BlackboardAttribute(self.att_payload_type, self.moduleName, str(notification["PayloadType"])))
                        art.addAttribute(BlackboardAttribute(self.att_payload, self.moduleName, str(notification["Payload"])))
                        expiry_time = self.windows_filetime_to_epoch(notification["ExpiryTime"])
                        art.addAttribute(BlackboardAttribute(self.att_expiry_time, self.moduleName, expiry_time))
                        arrival_time = self.windows_filetime_to_epoch(notification["ArrivalTime"])
                        art.addAttribute(BlackboardAttribute(self.att_arrival_time, self.moduleName, arrival_time))

                        self.index_artifact(blackboard, art, self.art_notification)
            self.log(Level.INFO, "Processed successfully...")

        #Post a message to the ingest messages in box.
        message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
            "Notifications Analyzer Data Source Ingest Module", "[NA] Finished processing %d Notification databases" % num_files)
        IngestServices.getInstance().postMessage(message)

        return IngestModule.ProcessResult.OK

    def windows_filetime_to_epoch(self, windows_filetime):
        return windows_filetime / 10000000 - 11644473600

    def index_artifact(self, blackboard, artifact, artifact_type):
        try:
            # Index the artifact for keyword search
            blackboard.indexArtifact(artifact)
        except Blackboard.BlackboardException as e:
            self.log(Level.INFO, "Error indexing artifact " + artifact.getDisplayName() + " " +str(e))
        # Fire an event to notify the UI and others that there is a new log artifact
        IngestServices.getInstance().fireModuleDataEvent(
            ModuleDataEvent(self.moduleName, artifact_type, None))

    def create_artifact_type(self, art_name, art_desc, blackboard):
        try:
            art = blackboard.getOrAddArtifactType(art_name, "NA: " + art_desc)
            # self.art_list.append(art)
        except Exception as e :
            self.log(Level.INFO, "Error getting or adding artifact type: " + art_desc + " " + str(e))
        return art

    def create_attribute_type(self, att_name, type_name, att_desc, blackboard):
        try:
            att_type = blackboard.getOrAddAttributeType(att_name, type_name, att_desc)
        except Exception as e:
            self.log(Level.INFO, "Error getting or adding attribute type: " + att_desc + " " + str(e))
        return att_type
    
    def process_recovery(self, db_path, file, blackboard):
        self.log(Level.INFO, "Starting recovery for " + file.getName())
        if PlatformUtil.isWindowsOS() and self.use_undark:
            path_to_undark = os.path.join(os.path.dirname(os.path.abspath(__file__)), "undark.exe")
            try:
                with open(self.temp_dir + '\\freespace.txt','w') as f:
                    subprocess.Popen([path_to_undark,'-i', db_path, '--freespace'],stdout=f).communicate()
                with open(self.temp_dir + '\\freespace.txt','r') as f:
                    line = f.readline()
                    while line:
                        art = file.newArtifact(self.art_freespace.getTypeID())
                        art.addAttribute(BlackboardAttribute(self.att_rec_row, self.moduleName, str(line)))
                        self.index_artifact(blackboard, art,self.art_freespace)
                        line = f.readline()
            except Exception as e:
                self.log(Level.SEVERE, str(e))
        if self.use_mdg:
            try:
                mdg = mdgMod.mdg_modified.sqlite_rec(db_path)
                res = mdg.extract_deleted()
                for line in res:
                    art = file.newArtifact(self.art_dp.getTypeID())
                    art.addAttribute(BlackboardAttribute(self.att_dp_type, self.moduleName, str(line[0])))
                    art.addAttribute(BlackboardAttribute(self.att_dp_offset, self.moduleName, str(line[1])))
                    art.addAttribute(BlackboardAttribute(self.att_dp_length, self.moduleName, str(line[2])))
                    art.addAttribute(BlackboardAttribute(self.att_dp_data, self.moduleName, str(line[3])))
                    self.index_artifact(blackboard, art,self.art_dp)
            except Exception as e:
                self.log(Level.SEVERE, str(e))
        self.log(Level.INFO, "Finished recovery for " + file.getName())
    
    def process_wal_files(self, file, file_manager, data_source, blackboard, b2lite):
        wal_files = file_manager.findFiles(data_source, "%.db-wal", file.getParentPath())

        for wal_file in wal_files:
            wal_path = os.path.join(self.temp_dir, str(wal_file.getName()))
            ContentUtils.writeToFile(wal_file, File(wal_path))
            if self.use_crawler:
                self.wal_crawl(wal_file, wal_path, blackboard)
            if self.use_b2l:
                self.wal_2lite(b2lite, wal_file, wal_path, blackboard)

    def is_text(self, tester):
        return tester == 'TEXT'

    def db_2lite(self, b2lite, db_file, db_path, blackboard):
        if self.use_b2l:
            try:
                sqlite_data = b2lite.process_sqlite(db_path)
                if sqlite_data:
                    for sqlite_frame in sqlite_data:
                        for page, outer_frame in sqlite_frame['body'].iteritems():
                            if 'page' in outer_frame:
                                self.process_b2l_row(blackboard, self.art_db_body_b2l, db_file, page, outer_frame['page'])        
                self.log(Level.INFO, "Successfully brought 2 lite " + db_file.getName())
            except Exception as e:
                self.log(Level.INFO, "Failed to bring DB 2 lite " + db_file.getName())
                self.log(Level.SEVERE, str(e))
    
    def wal_2lite(self, b2lite, wal_file, wal_path, blackboard):
        try:
            wal_data = b2lite.process_wal(wal_path)
            self.log(Level.INFO, "Successfully brought 2 lite " + wal_file.getName())
            if wal_data:
                for wal_frame in wal_data:
                    for page, outer_frame in wal_frame['wal'].iteritems():
                        self.process_b2l_row(blackboard, self.art_wal_b2l, wal_file, page, outer_frame)
                        
        except Exception as e:
            self.log(Level.INFO, "Failed to bring WAL 2 lite " + wal_file.getName())
            self.log(Level.SEVERE, str(e))

    def process_b2l_row(self, blackboard, art_type, file, page, outer_frame):
        for frame in outer_frame:
            if isinstance(frame, list):
                row = ""
                for y in frame:
                    if self.is_text(y[0]):
                        try:
                            row += str(y[1].decode('utf-8')) + ","
                        except UnicodeEncodeError:
                            row +=str(y[1]) + ","
                            continue
                    else:
                        row += str(y[1]) + ","
                art = file.newArtifact(art_type.getTypeID())
                art.addAttribute(BlackboardAttribute(self.att_b2l_page, self.moduleName, str(page)))
                art.addAttribute(BlackboardAttribute(self.att_b2l_row, self.moduleName, row))
                self.index_artifact(blackboard, art, art_type)

    def wal_crawl(self, wal_file, wal_path, blackboard):
        try:
            self.log(Level.INFO, "Crawling " + wal_file.getName())
            wal_matrix = wal_crawler.crawl(wal_path)
            self.log(Level.INFO, "Successfully crawled for " + wal_file.getName())
            
            for wal_row in wal_matrix:
                art = wal_file.newArtifact(self.art_wal_crawl.getTypeID())
                for header in wal_crawler.get_headers():
                    art.addAttribute(BlackboardAttribute(self.att_list_headers[header], self.moduleName, str(wal_row[header])))
                
                self.index_artifact(blackboard, art, self.art_wal_crawl)

        except Exception as e:
            self.log(Level.INFO, "Failed to crawl for " + wal_file.getName())
            self.log(Level.SEVERE, str(e))

# UI that is shown to user for each ingest job so they can configure the job.
class NotificationAnalyzerWithUISettingsPanel(IngestModuleIngestJobSettingsPanel):
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

    def checkBoxEventUndark(self, event):
        if self.checkboxUndark.isSelected():
            self.local_settings.setSetting("undark", "true")
        else:
            self.local_settings.setSetting("undark", "false")

    def checkBoxEventMdg(self, event):
        if self.checkboxMdg.isSelected():
            self.local_settings.setSetting("mdg", "true")
        else:
            self.local_settings.setSetting("mdg", "false")

    def checkBoxEventCrawler(self, event):
        if self.checkboxCrawler.isSelected():
            self.local_settings.setSetting("crawler", "true")
        else:
            self.local_settings.setSetting("crawler", "false")

    def checkBoxEventB2l(self, event):
        if self.checkboxB2l.isSelected():
            self.local_settings.setSetting("b2l", "true")
        else:
            self.local_settings.setSetting("b2l", "false")
    
    def textFieldEventPythonPath(self, event):
        self.local_settings.setSetting("python_path", self.textFieldPythonPath.getText())

    def initComponents(self):
        self.setLayout(BoxLayout(self, BoxLayout.Y_AXIS))
        # self.setLayout(GridLayout(0,1))
        self.setAlignmentX(JComponent.LEFT_ALIGNMENT)
        panel1 = JPanel()
        panel1.setLayout(BoxLayout(panel1, BoxLayout.Y_AXIS))
        panel1.setAlignmentY(JComponent.LEFT_ALIGNMENT)
        self.labelPythonPathText = JLabel("Python path: ")
        self.textFieldPythonPath = JTextField(1)
        self.buttonSavePythonPath = JButton("Save", actionPerformed=self.textFieldEventPythonPath)

        self.labelCheckText = JLabel("Run recoveries: ")

        self.checkboxUndark = JCheckBox("Undark", actionPerformed=self.checkBoxEventUndark)
        self.checkboxMdg = JCheckBox("MGD Delete Parser", actionPerformed=self.checkBoxEventMdg)
        self.checkboxCrawler = JCheckBox("WAL Crawler", actionPerformed=self.checkBoxEventCrawler)
        self.checkboxB2l = JCheckBox("bring2lite", actionPerformed=self.checkBoxEventB2l)
        
        self.checkboxUndark.setSelected(True)
        self.checkboxMdg.setSelected(True)
        
        self.add(self.labelPythonPathText)
        panel1.add(self.textFieldPythonPath)
        panel1.add(self.buttonSavePythonPath)

        panel1.add(self.labelCheckText)
        panel1.add(self.checkboxUndark)
        panel1.add(self.checkboxMdg)
        panel1.add(self.checkboxCrawler)
        panel1.add(self.checkboxB2l)
        self.add(panel1)

    def customizeComponents(self):
        # Set defaults if not set
        if not self.local_settings.getSetting("undark"):
            self.local_settings.setSetting("undark", "true")
        if not self.local_settings.getSetting("mdg"):
            self.local_settings.setSetting("mdg", "true")
        if not self.local_settings.getSetting("python_path"):
            self.local_settings.setSetting("python_path", "python")

        # Update checkboxes with stored settings
        self.checkboxUndark.setSelected(self.local_settings.getSetting("undark") == "true")
        self.checkboxMdg.setSelected(self.local_settings.getSetting("mdg") == "true")
        self.checkboxCrawler.setSelected(self.local_settings.getSetting("crawler") == "true")
        self.checkboxB2l.setSelected(self.local_settings.getSetting("b2l") == "true")
        self.textFieldPythonPath.setText(self.local_settings.getSetting("python_path"))

    # Return the settings used
    def getSettings(self):
        return self.local_settings