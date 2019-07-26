import os
import inspect
import bs4
import datetime
from urllib2 import urlopen
import time

from math import ceil
from java.lang import System
from java.util.logging import Level
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.casemodule.services import Services
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.coreutils import Version
from org.sleuthkit.autopsy.report import GeneralReportModuleAdapter
from org.sleuthkit.autopsy.report.ReportProgressPanel import ReportStatus
from org.sleuthkit.datamodel import AbstractFile

from javax.swing import JPanel
from javax.swing import JComboBox
from javax.swing import JLabel
from java.awt import FlowLayout
from java.awt import BorderLayout
from javax.swing import JFrame
from java.awt import Color
from db import db_functions

from java.awt.image import BufferedImage
from java.io import File, ByteArrayOutputStream, ByteArrayInputStream, File
from javax.imageio import ImageIO
from java.lang import NullPointerException

COLLAPSE_PREFIX = "collapsechat"
HTML_COLLAPSE_PREFIX = "#" + COLLAPSE_PREFIX
MODAL_PREFIX = "modal"
HTML_MODAL_PREFIX = "#" + MODAL_PREFIX
CONVERSATION_PREFIX = "chat"
SELF_MESSAGE_DEFAULT = "n/a (self)"
SELF_USER = "Self"
NUM_ARTIFACTS_PROGRESS = 10

class YourPhoneAnalyzerGeneralReportModule(GeneralReportModuleAdapter):

    moduleName = "YPA Report"

    _logger = None

    def log(self, level, msg):
        if self._logger is None:
            self._logger = Logger.getLogger(self.moduleName)
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def getName(self):
        return self.moduleName

    def getDescription(self):
        return "Report of Your Phone Analyzer ingest module"

    def getRelativeFilePath(self):
        return "YPA_" + Case.getCurrentCase().getName() + ".html"

    def getRelativeFilePathAddressBook(self):
        return "YPA_AddressBook_" + Case.getCurrentCase().getName() + ".html"
    
    def getRelativeFilePathPhotos(self):
        return "YPA_Photos_" + Case.getCurrentCase().getName() + ".html"

    def write_conversation_to_html(self, progressBar, art_count, artifact, html_file):
        row = html_file.new_tag("tr")

        # Get artifact's attributes
        attributes = artifact.getAttributes()
        for attribute in attributes:
            attribute_value = attribute.getDisplayString()
            cell = html_file.new_tag("td")
            cell.string = attribute_value

            # Append cell to the row
            row.append(cell)


        # Update progress bar every 10 artifacts
        if art_count % NUM_ARTIFACTS_PROGRESS == 0:
            progressBar.increment()

        return row

    def get_sanitized_address(self, address):
        return address.replace('+','plus')

    def add_msg_to_html_report(self, html_file, thread_id, body, timestamp, from_user, address, username):
        html_chat_id = HTML_COLLAPSE_PREFIX + thread_id
        div_msg = html_file.new_tag("div")
        span_time = html_file.new_tag("span")

        if from_user == None or from_user == SELF_MESSAGE_DEFAULT:
            div_msg['class'] = "container darker"
            from_user = SELF_USER
            span_time['class'] = "time-left"
        else:
            div_msg['class'] = "container text-right"
            div_msg['data-toggle'] = "modal"
            div_msg['data-target'] = HTML_MODAL_PREFIX + self.get_sanitized_address(address) + username
            span_time['class'] = "time-right"


        p_sender = html_file.new_tag("p")
        p_bold_sender = html_file.new_tag("b")
        p_bold_sender.string = from_user
        p_sender.append(p_bold_sender)
        p_msg_body = html_file.new_tag("p")
        p_msg_body.string = body
        span_time.string = timestamp

        div_msg.append(p_sender)
        div_msg.append(p_msg_body)
        div_msg.append(span_time)

        # self.log(Level.INFO, "HTML CHAT ID: " + html_chat_id)
        chat = html_file.select(html_chat_id)[0]
        chat.append(div_msg)

    def add_chat_to_html_report(self, html_file, chat_id, thread_id, username):
        html_chat_id = HTML_COLLAPSE_PREFIX + thread_id
        div_chat_id = COLLAPSE_PREFIX + thread_id

        # Add chat to sidebar
        a_chat = html_file.new_tag("a")
        a_chat['class'] = "list-group-item list-group-item-action bg-light"
        a_chat['data-toggle'] = "collapse"
        a_chat['id'] = CONVERSATION_PREFIX + thread_id
        a_chat['href'] = html_chat_id
        a_chat.string = chat_id

        chats = html_file.select("#sidebar-chats")[0]
        chats.append(a_chat)

        # Add chat collapseable
        div_chat = html_file.new_tag("div")
        div_chat['class'] = "container-fluid collapse multi-collapse"
        div_chat['id'] = div_chat_id
        div_chat['data-parent'] = "#page-content-wrapper"

        collapseable_chats = html_file.select("#page-content-wrapper")[0]
        collapseable_chats.append(div_chat)

    def add_contact_modal(self, html_file, artifact, id, username):
        div_modal = html_file.new_tag("div")
        div_modal['class'] = "modal fade"
        div_modal['id'] = MODAL_PREFIX + self.get_sanitized_address(id) + username
        div_modal['role'] = "dialog"
        div_modal['tabindex'] = "-1"

        div_dialog = html_file.new_tag("div")
        div_dialog['class'] = "modal-dialog"
        div_dialog['role'] = "document"
        div_modal.append(div_dialog)

        div_content = html_file.new_tag("div")
        div_content['class'] = "modal-content"
        div_dialog.append(div_content)

        div_header = html_file.new_tag("div")
        div_header['class'] = "modal-header"
        div_content.append(div_header)

        h_title = html_file.new_tag("h5")
        h_title['class'] = "modal-title"
        h_title.string = "Contact details"
        div_header.append(h_title)

        button_close = html_file.new_tag("button")
        button_close['class'] = "close"
        button_close['data-dismiss'] = "modal"
        div_header.append(button_close)

        span_close = html_file.new_tag("span")
        span_close.string = "x"
        button_close.append(span_close)

        div_body = html_file.new_tag("div")
        div_body['class'] = "modal-body"

        for attribute in artifact.getAttributes():
            p_attribute = html_file.new_tag("p")
            b_attribute_display = html_file.new_tag("b")
            b_attribute_display.string = attribute.getAttributeType().getDisplayName()
            p_attribute.string = attribute.getDisplayString()
            div_body.append(b_attribute_display)
            div_body.append(p_attribute)

        div_content.append(div_body)

        html_body = html_file.select("#page-content-wrapper")[0]
        html_body.append(div_modal)
    
    def add_photo_modal(self, html_file, path, id, username):
        div_modal = html_file.new_tag("div")
        div_modal['class'] = "modal fade"
        div_modal['id'] = MODAL_PREFIX + id + username
        div_modal['role'] = "dialog"
        div_modal['tabindex'] = "-1"

        div_dialog = html_file.new_tag("div")
        div_dialog['class'] = "modal-dialog modal-xl"
        div_dialog['role'] = "document"
        div_modal.append(div_dialog)

        div_content = html_file.new_tag("div")
        div_content['class'] = "modal-content"
        div_dialog.append(div_content)

        div_header = html_file.new_tag("div")
        div_header['class'] = "modal-header"
        div_content.append(div_header)

        h_title = html_file.new_tag("h5")
        h_title['class'] = "modal-title"
        h_title.string = "Zoomed photo"
        div_header.append(h_title)

        button_close = html_file.new_tag("button")
        button_close['class'] = "close"
        button_close['data-dismiss'] = "modal"
        div_header.append(button_close)

        span_close = html_file.new_tag("span")
        span_close.string = "x"
        button_close.append(span_close)

        div_body = html_file.new_tag("div")
        div_body['class'] = "modal-body"

        img = html_file.new_tag("img")
        img['src'] = path
        div_body.append(img)

        div_content.append(div_body)

        html_body = html_file.select("#page-content-wrapper")[0]
        html_body.append(div_modal)

    def add_total_msgs_to_chat(self, html_file, thread_id, num_msgs, timestamp):
        conversation = html_file.select("#" + CONVERSATION_PREFIX + thread_id)[0]
        i_total_messages = html_file.new_tag("i")
        i_total_messages.string = " - " + str(num_msgs) + " messages"

        span_time = html_file.new_tag("span")
        span_time['class'] = "time-left"
        span_time.string = timestamp

        conversation.append(i_total_messages)
        conversation.append(span_time)

    def create_tr_for_table(self, html_file, username, id, list_att):
        tr = html_file.new_tag("tr")

        td_user = html_file.new_tag("td")
        td_user.string = username

        tr.append(td_user)
        th_id = html_file.new_tag("th")
        th_id['scope'] = "row"
        th_id.string = id

        tr.append(th_id)

        for attribute in list_att:
            td = html_file.new_tag("td")

            if attribute == "1970-01-01 00:00:00":
                td.string = "---"
            else:
                td.string = attribute

            tr.append(td)
        return tr

    def add_to_address_book(self, html_file, contact_id, list_att, username):
        tr_address = self.create_tr_for_table(html_file, username, contact_id, list_att)

        address_book = html_file.select("#address-book-table")[0]
        address_book.append(tr_address)
    
    def add_to_photos(self, html_file, username, photo_id, path, list_att):
        tr_photo = self.create_tr_for_table(html_file, username, photo_id, list_att)

        td = html_file.new_tag("td")
        img = html_file.new_tag("img")
        img['src'] = path
        img['width'] = "200"
        img['height'] = "200"
        img['alt'] = "Image error"
        td.append(img)
        tr_photo.append(td)


        img['data-toggle'] = "modal"
        img['data-target'] = HTML_MODAL_PREFIX + photo_id + username

        photos = html_file.select("#photo-table")[0]
        photos.append(tr_photo)

    def add_to_contact_book(self, html_file, display_name, address, timestamp, username):
        # Add chat to sidebar
        a_chat = html_file.new_tag("a")
        a_chat['class'] = "list-group-item list-group-item-action bg-light"
        a_chat['data-toggle'] = "modal"
        a_chat['data-target'] = HTML_MODAL_PREFIX + self.get_sanitized_address(address) + username
        a_chat.string = display_name

        span_time = html_file.new_tag("span")
        span_time['class'] = "time-left"
        span_time.string = timestamp
        a_chat.append(span_time)

        contacts = html_file.select("#sidebar-contacts")[0]
        contacts.append(a_chat)

    def increment_progress_bar(self, progressBar, art_count):
        if art_count % NUM_ARTIFACTS_PROGRESS == 0:
            progressBar.increment()
        return art_count + 1

    def add_link_to_html_report(self, report, tag, link_to):
        link = report.select(tag)[0]
        link['href'] = link_to

    def save_photo(self, photo_bytes, base_dir, name):
        path = os.path.join(base_dir, name)
        try:
            bis = ByteArrayInputStream(photo_bytes)
            b_image = ImageIO.read(bis)
            ImageIO.write(b_image, "jpg", File(path))
        except Exception as e:
            self.log(Level.SEVERE, "Error saving photo: " + str(e))
        return path
    
    # The 'baseReportDir' object being passed in is a string with the directory that reports are being stored in.   Report should go into baseReportDir + getRelativeFilePath().
    # The 'progressBar' object is of type ReportProgressPanel.
    #   See: http://sleuthkit.org/autopsy/docs/api-docs/4.4/classorg_1_1sleuthkit_1_1autopsy_1_1report_1_1_report_progress_panel.html
    def generateReport(self, baseReportDir, progressBar):
        self.log(Level.INFO, "Starting YPA report module")

        self.temp_dir = Case.getCurrentCase().getTempDirectory()
        # Count execution time
        start_time = time.time()

        # Configure progress bar for 2 tasks
        progressBar.setIndeterminate(False)
        progressBar.start()
        progressBar.updateStatusLabel("Getting artifacts...")

        skCase = Case.getCurrentCase().getSleuthkitCase()


        # Get artifact lists
        # art_list_custom_regex = skCase.getMatchingArtifacts("JOIN blackboard_artifact_types AS types ON blackboard_artifacts.artifact_type_id = types.artifact_type_id WHERE types.type_name LIKE 'TSK_LFA_CUSTOM_REGEX_%'")

        art_list_messages = skCase.getMatchingArtifacts("JOIN blackboard_artifact_types AS types ON blackboard_artifacts.artifact_type_id = types.artifact_type_id WHERE types.type_name LIKE 'YPA_MESSAGE_%'")
        art_list_contacts = skCase.getMatchingArtifacts("JOIN blackboard_artifact_types AS types ON blackboard_artifacts.artifact_type_id = types.artifact_type_id WHERE types.type_name LIKE 'YPA_CONTACTS_%'")
        art_list_photos = skCase.getMatchingArtifacts("JOIN blackboard_artifact_types AS types ON blackboard_artifacts.artifact_type_id = types.artifact_type_id WHERE types.type_name LIKE 'YPA_PHOTO_%'")
        total_artifact_count = len(art_list_messages) + len(art_list_contacts) + len(art_list_photos)



        if total_artifact_count == 0:
            msg = "There seem to be no YPA artifacts. Did you run the ingest module? Please cancel this report and try again after the ingest module."
            progressBar.updateStatusLabel("WARNING: " + msg)
            self.log(Level.SEVERE, msg)
            progressBar.complete(ReportStatus.ERROR)
            return

        # Progress bar shouldn't be updated too frequently
        # So we'll update it every X artifacts (defined by a constant)
        # Plus 2 for 2 additional steps
        max_progress = (ceil(total_artifact_count / NUM_ARTIFACTS_PROGRESS) + 2)
        progressBar.setMaximumProgress(int(max_progress))

        # First additional step here
        progressBar.increment()
        progressBar.updateStatusLabel("Creating report(s)")

        # Get html_file_name
        html_file_name = os.path.join(baseReportDir, self.getRelativeFilePath())
        # Get template path
        template_name_chats = os.path.join(os.path.dirname(os.path.abspath(__file__)), "template_chats.html")

        # Get html_file_name
        html_file_name_book = os.path.join(baseReportDir, self.getRelativeFilePathAddressBook())
        # Get template path
        template_name_book = os.path.join(os.path.dirname(os.path.abspath(__file__)), "template_address_book.html")

        # Get html_file_name
        html_file_name_photos = os.path.join(baseReportDir, self.getRelativeFilePathPhotos())
        # Get template path
        template_name_photos = os.path.join(os.path.dirname(os.path.abspath(__file__)), "template_photos.html")

        with open(template_name_chats) as base_dir:
            txt = base_dir.read()
            html_ypa = bs4.BeautifulSoup(txt)

        with open(template_name_book) as base_dir:
            txt = base_dir.read()
            html_ypa_book = bs4.BeautifulSoup(txt)
        
        with open(template_name_photos) as base_dir:
            txt = base_dir.read()
            html_ypa_photos = bs4.BeautifulSoup(txt)

        self.add_link_to_html_report(html_ypa, "#address-book", self.getRelativeFilePathAddressBook())
        self.add_link_to_html_report(html_ypa, "#photos", self.getRelativeFilePathPhotos())
        self.add_link_to_html_report(html_ypa_book, "#conversations", self.getRelativeFilePath())
        self.add_link_to_html_report(html_ypa_book, "#photos", self.getRelativeFilePathPhotos())
        self.add_link_to_html_report(html_ypa_photos, "#conversations", self.getRelativeFilePath())
        self.add_link_to_html_report(html_ypa_photos, "#address-book", self.getRelativeFilePathAddressBook())
        
        # Get Attribute types
        att_thread_id = skCase.getAttributeType("YPA_THREAD_ID")
        att_body = skCase.getAttributeType("YPA_BODY")
        att_timestamp = skCase.getAttributeType("YPA_TIMESTAMP")
        att_from_address = skCase.getAttributeType("YPA_FROM_ADDRESS")
        att_recipient_list = skCase.getAttributeType("YPA_RECIPIENT_LIST")

        att_contact_id = skCase.getAttributeType("YPA_CONTACT_ID")
        att_address = skCase.getAttributeType("YPA_ADDRESS")
        att_display_name = skCase.getAttributeType("YPA_DISPLAY_NAME")
        att_address_type = skCase.getAttributeType("YPA_ADDRESS_TYPE")
        att_times_contacted = skCase.getAttributeType("YPA_TIMES_CONTACTED")
        att_last_contacted = skCase.getAttributeType("YPA_LAST_CONTACT_TIME")
        att_last_updated = skCase.getAttributeType("YPA_LAST_UPDATE_TIME")

        att_photo_id = skCase.getAttributeType("YPA_PHOTO_ID")
        att_pic_size = skCase.getAttributeType("YPA_PIC_SIZE")
        att_uri = skCase.getAttributeType("YPA_URI")

        art_count = 0
        attribute_type = self.configPanel.getAttTypeList()[self.configPanel.getSelectedAddressBookOrderIndex()]
        for artifact in sorted(art_list_contacts, key = lambda (a): a.getAttribute(attribute_type).getDisplayString()):
            username = artifact.getArtifactTypeName().split('_')[-1]
            att_list = []
            contact_id = artifact.getAttribute(att_contact_id).getDisplayString()
            id_for_contact = artifact.getAttribute(att_address).getDisplayString()
            att_list.append(id_for_contact)
            att_list.append(artifact.getAttribute(att_display_name).getDisplayString())
            att_list.append(artifact.getAttribute(att_address_type).getDisplayString())
            att_list.append(artifact.getAttribute(att_times_contacted).getDisplayString())
            att_list.append(artifact.getAttribute(att_last_contacted).getDisplayString())
            att_list.append(artifact.getAttribute(att_last_updated).getDisplayString())
            self.add_contact_modal(html_ypa, artifact, id_for_contact, username)
            # self.add_to_contact_book(html_ypa, display_name, id_for_contact, last_contacted)
            self.add_to_address_book(html_ypa_book, contact_id, att_list, username)
            art_count = self.increment_progress_bar(progressBar, art_count)

        dict_thread_ids = {}
        for artifact in art_list_messages:
            username = artifact.getArtifactTypeName().split('_')[-1]
            # Overall chat details
            thread_id = artifact.getAttribute(att_thread_id).getValueString() + username
            display_name = artifact.getAttribute(att_display_name).getValueString()
            chat_name = artifact.getAttribute(att_recipient_list).getValueString() + " (user: " + username + ")"
            address = artifact.getAttribute(att_from_address).getValueString()
            sender = display_name + " (" + address + ")"

            # Message details
            body = artifact.getAttribute(att_body).getValueString()
            timestamp = artifact.getAttribute(att_timestamp).getValueString()
            if not dict_thread_ids.get(thread_id):
                # Create Chat
                dict_thread_ids[thread_id] = [1, timestamp]
                self.add_chat_to_html_report(html_ypa, chat_name, thread_id, username)
            else:
                dict_thread_ids[thread_id][0] += 1
                dict_thread_ids[thread_id][1] = timestamp

            self.add_msg_to_html_report(html_ypa, thread_id, body, timestamp, sender, address, username)

            art_count = self.increment_progress_bar(progressBar, art_count)

        for (t_id, t_list) in dict_thread_ids.iteritems():
            self.add_total_msgs_to_chat(html_ypa, t_id, t_list[0], t_list[1])

        progressBar.updateStatusLabel("Generating photos from BLOBs")

        for artifact in art_list_photos:
            photo_id = artifact.getAttribute(att_photo_id).getValueString()
            name = artifact.getAttribute(att_display_name).getValueString()
            last_updated = artifact.getAttribute(att_last_updated).getValueString()
            size = artifact.getAttribute(att_pic_size).getValueString()
            uri = artifact.getAttribute(att_uri).getValueString()
            # TO-DO: Optimize DB connections
            username = artifact.getArtifactTypeName().split('_')[-1]
            source_file = skCase.getAbstractFileById(artifact.getObjectID())
            db_conn, db_path = db_functions.create_db_conn(self, source_file)
            query = "select thumbnail, blob from photo where photo_id = " + photo_id
            rs = db_functions.execute_query(self, query, db_conn)
            rs.next()
            
            path = self.save_photo(rs.getBytes('blob'), baseReportDir, name)
            self.add_photo_modal(html_ypa_photos, path, photo_id, username)
            self.add_to_photos(html_ypa_photos, username, photo_id, path, [name, last_updated, size, uri])

            db_functions.close_db_conn(self, db_conn, db_path)

        progressBar.updateStatusLabel("Saving report")

        with open(html_file_name, "w") as outf:
            outf.write(str(html_ypa))

        with open(html_file_name_book, "w") as outf:
            outf.write(str(html_ypa_book))
        
        with open(html_file_name_photos, "w") as outf:
            outf.write(str(html_ypa_photos))

        Case.getCurrentCase().addReport(html_file_name, self.moduleName, "YPA Report")

        # Elapsed time
        elapsed_time = time.time() - start_time

        self.log(Level.INFO, "YPA Report module took "+str(elapsed_time) + "s")

        # Call this with ERROR if report was not generated
        progressBar.complete(ReportStatus.COMPLETE)

    def getConfigurationPanel(self):
        self.configPanel = LFA_ConfigPanel()
        return self.configPanel

#########################################################################
#   _____                __  _          _____                     _     #
#  / ____|              / _|(_)        |  __ \                   | |    #
# | |      ___   _ __  | |_  _   __ _  | |__) |__ _  _ __    ___ | |    #
# | |     / _ \ | '_ \ |  _|| | / _` | |  ___// _` || '_ \  / _ \| |    #
# | |____| (_) || | | || |  | || (_| | | |   | (_| || | | ||  __/| |    #
#  \_____|\___/ |_| |_||_|  |_| \__, | |_|    \__,_||_| |_| \___||_|    #
#                                __/ |                                  #
#                               |___/                                   #
#########################################################################

class LFA_ConfigPanel(JPanel):

    def __init__(self):
        self.initComponents()

    def getSelectedAddressBookOrderIndex(self):
        return self.orderComboBox.getSelectedIndex()

    def getAttTypeList(self):
        return self.att_type_list

    def initComponents(self):
        skCase = Case.getCurrentCase().getSleuthkitCase()
        att_contact_id = skCase.getAttributeType("YPA_CONTACT_ID")
        att_address = skCase.getAttributeType("YPA_ADDRESS")
        att_display_name = skCase.getAttributeType("YPA_DISPLAY_NAME")
        att_address_type = skCase.getAttributeType("YPA_ADDRESS_TYPE")
        att_times_contacted = skCase.getAttributeType("YPA_TIMES_CONTACTED")
        att_last_contacted = skCase.getAttributeType("YPA_LAST_CONTACT_TIME")
        att_last_updated = skCase.getAttributeType("YPA_LAST_UPDATE_TIME")

        self.att_type_list = [att_contact_id, att_address, att_display_name, att_address_type, att_times_contacted, att_last_updated, att_last_contacted]
        
        orderOptions = []
        for att in self.att_type_list:
            orderOptions.append(att.getDisplayName())
        self.setLayout(FlowLayout())

        descriptionLabel = JLabel(" YPA - Your Phone Analyzer (Report module)")
        self.add(descriptionLabel)

        orderLabel = JLabel("Address book order: ")
        self.add(orderLabel)

        self.orderComboBox = JComboBox(orderOptions)
        self.add(self.orderComboBox)

        pnl = JPanel()
        pnl.add(self.orderComboBox)
        self.add(pnl)


        art_count = len(skCase.getMatchingArtifacts("JOIN blackboard_artifact_types AS types ON blackboard_artifacts.artifact_type_id = types.artifact_type_id WHERE types.type_name LIKE 'YPA_%'"))
        if art_count == 0:
            warningLabel = JLabel(" WARNING: Please run the ingest module before this report module.")
            warningLabel.setForeground(Color.RED)
            self.add(warningLabel)