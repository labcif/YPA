import os
import inspect
import bs4
import datetime
from urllib2 import urlopen
import time

from math import ceil
from java.lang import System
from java.util import Date, TimeZone
from java.text import SimpleDateFormat
from java.sql import SQLException
from java.util.logging import Level
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.casemodule.services import Services
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.coreutils import Version
from org.sleuthkit.autopsy.report import GeneralReportModuleAdapter
from org.sleuthkit.autopsy.report.ReportProgressPanel import ReportStatus
from org.sleuthkit.autopsy.datamodel import ContentUtils
from org.sleuthkit.datamodel import AbstractFile
from org.sleuthkit.datamodel import BlackboardAttribute

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
from java.nio.file import Files
from javax.imageio import ImageIO
from java.lang import NullPointerException

COLLAPSE_PREFIX = "collapsechat"
HTML_COLLAPSE_PREFIX = "#" + COLLAPSE_PREFIX
MODAL_PREFIX = "modal"
HTML_MODAL_PREFIX = "#" + MODAL_PREFIX
CONVERSATION_PREFIX = "chat"
NOT_AVAILABLE = "n/a"
SELF_MESSAGE_DEFAULT = NOT_AVAILABLE + " (Self)"
SELF_USER = "Self"
NUM_ARTIFACTS_PROGRESS = 10
IMAGE_EXTENSION = ".jpg"
DEFAULT_PHOTO = "default" + IMAGE_EXTENSION
PHOTO_MEDIA_QUERY = "SELECT m.thumbnail, media, m.id \
                FROM media m \
                LEFT JOIN photo p on m.name = p.name \
                WHERE id = "
CONTACT_THUMBNAIL_QUERY = "SELECT thumbnail, contact_id FROM contact WHERE contact_id = "\

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
        
    def getRelativeFilePathCallHistory(self):
        return "YPA_CallHistory_" + Case.getCurrentCase().getName() + ".html"
    
    def getRelativeFilePathPhoneApps(self):
        return "YPA_PhoneApps_" + Case.getCurrentCase().getName() + ".html"
    
    def get_file_by_artifact(self, skCase, artifact):
        return skCase.getAbstractFileById(artifact.getObjectID())

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

    def add_msg_to_html_report(self, html_file, thread_id, body, timestamp, from_user, address, username, guid):
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
            div_msg['data-target'] = HTML_MODAL_PREFIX + self.get_sanitized_address(address) + guid + username 
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

        # Fullsize button<button type="button" class="btn btn-primary">Primary</button>
        button = html_file.new_tag("a")
        button['href'] = path
        button['class'] = "btn btn-primary"
        button.string = "Open in fullscreen"
        # button['target'] = "_blank"
        div_header.append(button)

        button_close = html_file.new_tag("button")
        button_close['class'] = "close"
        button_close['data-dismiss'] = "modal"
        div_header.append(button_close)

        span_close = html_file.new_tag("span")
        span_close.string = "x"
        button_close.append(span_close)

        div_body = html_file.new_tag("div")
        div_body['class'] = "modal-body"
        
        # Image
        img = html_file.new_tag("img")
        img['src'] = path
        img['class'] = "img-fluid"
        div_body.append(img)

        div_content.append(div_body)

        html_body = html_file.select("#page-content-wrapper")[0]
        html_body.append(div_modal)

    def add_total_msgs_to_chat(self, html_file, thread_id, num_msgs, timestamp, display_name):
        conversation = html_file.select("#" + CONVERSATION_PREFIX + thread_id)[0]
        i_total_messages = html_file.new_tag("i")
        if num_msgs == 1:
            str_messages = " message"
        else:
            str_messages = " messages"
        i_total_messages.string = " " + display_name + " - " + str(num_msgs) + str_messages

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

        if id is not None:
            th_id = html_file.new_tag("th")
            th_id['scope'] = "row"
            th_id.string = id

            tr.append(th_id)

        for attribute in list_att:
            td = html_file.new_tag("td")

            # Rules that apply to certain attributes
            if attribute == "Incoming":
                self.add_icon_to_parent(html_file, td, "call_received")
            if attribute == "Outgoing":
                self.add_icon_to_parent(html_file, td, "call_made")
            if attribute == "Missed":
                self.add_icon_to_parent(html_file, td, "call_missed")
            if attribute == "Declined":
                self.add_icon_to_parent(html_file, td, "call_missed_outgoing")

            if attribute == "1970-01-01T00:00:00Z":
                td.string = "---"
            else:
                td.append(attribute)

            tr.append(td)
        return tr
    
    def add_icon_to_parent(self, html_file, parent, icon_id):
        icon = html_file.new_tag("i")
        icon['class'] = "material-icons"
        icon.string = icon_id
        parent.append(icon)

    def add_to_address_book(self, html_file, contact_id, list_att, username, thumbnail_path):
        tr_address = self.create_tr_for_table(html_file, username, contact_id, list_att)

        self.add_photo_to_parent(html_file, tr_address, thumbnail_path)

        address_book = html_file.select("#address-book-table")[0]
        address_book.append(tr_address)
    
    def add_to_call_history(self, html_file, call_id, list_att, username):
        tr_call = self.create_tr_for_table(html_file, username, call_id, list_att)

        call_history = html_file.select("#call-history-table")[0]
        call_history.append(tr_call)
    
    def add_to_phone_apps(self, html_file, att_list, play_store_link, username, app_name):
        modal_id = MODAL_PREFIX + username + app_name
        tr_app = self.create_tr_for_table(html_file, username, None, att_list)

        # Add play store link
        td_link = html_file.new_tag("td")
        a_link = html_file.new_tag("a")
        a_link['href'] = play_store_link
        a_link.string = "Link"

        td_link.append(a_link)
        tr_app.append(td_link)

        # Notifications
        div_modal = html_file.find(id = modal_id)
        if div_modal is not None:
            td_button = html_file.new_tag("td")
            button_notif = html_file.new_tag("button")
            button_notif['class'] = "btn btn-primary"
            button_notif['data-toggle'] = "modal"
            button_notif['data-target'] = HTML_MODAL_PREFIX + username + app_name
            button_notif.string = "Open"
            
            td_button.append(button_notif)
            tr_app.append(td_button)

        phone_apps = html_file.select("#phone-apps-table")[0]
        phone_apps.append(tr_app)

    def add_to_phone_app_notifications(self, html_file, artifact, username, app_name, is_xml, index):
        modal_id = MODAL_PREFIX + username + app_name
        div_modal = html_file.find(id = modal_id)
        
        if div_modal is None:
            div_modal = html_file.new_tag("div")
            div_modal['class'] = "modal fade"
            div_modal['id'] = modal_id
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
            h_title.string = "Notifications"
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

            div_content.append(div_body)

            html_body = html_file.select("#page-content-wrapper")[0]
            html_body.append(div_modal)
        else:
            hr = html_file.new_tag("hr")
            
            div_body = div_modal.find(class_ = "modal-body")
            div_body.append(hr)
        
        header_notif = html_file.new_tag("h5")
        header_notif.string = "Notification " + str(index)
        div_body.append(header_notif)

        for attribute in artifact.getAttributes():
            att_display_name = attribute.getAttributeType().getDisplayName()
            p_attribute = html_file.new_tag("p")
            b_attribute_display = html_file.new_tag("b")
            b_attribute_display.string = att_display_name
            att_type = attribute.getValueType()
            if att_type is BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME:
                p_attribute.string = self.unix_to_date_string(attribute.getValueLong())
            else:
                if att_display_name == "Payload" and is_xml:
                    pre = html_file.new_tag("pre")
                    pre.string = attribute.getDisplayString()

                    div_body.append(pre)
                else:
                    p_attribute.string = attribute.getDisplayString()
            div_body.append(b_attribute_display)
            div_body.append(p_attribute)
    
    def add_to_photos(self, html_file, username, photo_id, media_id, path, list_att):
        tr_photo = self.create_tr_for_table(html_file, username, photo_id, list_att)

        img = self.add_photo_to_parent(html_file, tr_photo, path)
        
        img['data-toggle'] = "modal"
        img['data-target'] = HTML_MODAL_PREFIX + media_id + username

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
            self.saved_photos.append(name)
        except Exception as e:
            self.log(Level.SEVERE, "Error saving photo: " + str(e))
        return path

    def add_photo_to_parent(self, html_file, parent, photo_path):
        td = html_file.new_tag("td")
        img = html_file.new_tag("img")
        if photo_path not in self.saved_photos:
            photo_path = DEFAULT_PHOTO
        img['src'] = photo_path
        # img['width'] = "200"
        # img['height'] = "200"
        img['class'] = "img-fluid img-thumbnail"
        img['alt'] = "No image available"
        td.append(img)
        parent.append(td)
        return img
    
    def unix_to_date_string(self, unix):
        date = Date(unix * 1000)
        df = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssX")
        df.setTimeZone(TimeZone.getTimeZone("UTC"))
        return df.format(date)
    
    def get_image_bytes(self, artifact, skCase, query, name = "Undefined name"):
        artifact_obj_id = artifact.getObjectID()
        source_file = self.get_file_by_artifact(skCase, artifact)

        if not source_file or not source_file.exists():
            # getAbstractFileById can return null.
            # Skip this photo in case source DB is not available.
            self.log(Level.INFO, "No source DB for " + name)
            return None
        
        # If the DB is different, close old conn and create new one
        if self.db_conn and self.db_path and artifact_obj_id != self.last_obj_id:
            db_functions.close_db_conn(self, self.db_conn, self.db_path)
            self.db_conn, self.db_path = db_functions.create_db_conn(self, source_file)
        else:
            if not self.db_conn and not self.db_path:
                self.db_conn, self.db_path = db_functions.create_db_conn(self, source_file)
        
        try:
            rs, stmt = db_functions.execute_query(self, query, self.db_conn)
            image_bytes = None
            if rs and not rs.isClosed():
                rs.next()
                try:
                    image_bytes = rs.getBytes('media') or rs.getBytes('thumbnail')
                except SQLException:
                    image_bytes = rs.getBytes('thumbnail')
            else:
                self.log(Level.INFO, "No result or closed result for image " + name)

            rs.close()
            stmt.close()

            return image_bytes
        except Exception as e:
            self.log(Level.INFO, "WARNING: Failed to get image for " + name + " due to " + str(e))
        finally:
            self.last_obj_id = artifact_obj_id
    
    # The 'baseReportDir' object being passed in is a string with the directory that reports are being stored in.   Report should go into baseReportDir + getRelativeFilePath().
    # The 'progressBar' object is of type ReportProgressPanel.
    #   See: http://sleuthkit.org/autopsy/docs/api-docs/4.4/classorg_1_1sleuthkit_1_1autopsy_1_1report_1_1_report_progress_panel.html
    def generateReport(self, settings, progressBar):
        self.log(Level.INFO, "Starting YPA report module")

        self.temp_dir = Case.getCurrentCase().getTempDirectory()
        
        self.last_obj_id = None
        self.db_conn = None
        self.db_path = None
        self.saved_photos = []
        # Count execution time
        start_time = time.time()

        # Configure progress bar for 2 tasks
        progressBar.setIndeterminate(False)
        progressBar.start()
        progressBar.updateStatusLabel("Getting artifacts...")

        skCase = Case.getCurrentCase().getSleuthkitCase()

        # Get artifact lists
        # art_list_custom_regex = skCase.getMatchingArtifacts("JOIN blackboard_artifact_types AS types ON blackboard_artifacts.artifact_type_id = types.artifact_type_id WHERE types.type_name LIKE 'TSK_LFA_CUSTOM_REGEX_%'")

        base_query = "JOIN blackboard_artifact_types AS types ON blackboard_artifacts.artifact_type_id = types.artifact_type_id WHERE types.type_name LIKE "
        art_list_messages = skCase.getMatchingArtifacts(base_query + "'YPA_MESSAGE_%'")
        art_list_contacts = skCase.getMatchingArtifacts(base_query + "'YPA_CONTACTS_%'")
        art_list_photos = skCase.getMatchingArtifacts(base_query + "'YPA_PHOTO_%'")
        art_list_calls = skCase.getMatchingArtifacts(base_query + "'YPA_CALLING_%'")
        art_list_phone_apps = skCase.getMatchingArtifacts(base_query + "'YPA_PHONE_APP_%'")
        art_list_notifications = skCase.getMatchingArtifacts(base_query + "'NA_NOTIFICATION_%'")
        total_artifact_count = len(art_list_messages) + len(art_list_contacts) + len(art_list_photos) + len(art_list_calls) + len(art_list_phone_apps)

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

        baseReportDir = settings.getReportDirectoryPath()
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

        # Get html_file_name
        html_file_name_call_history = os.path.join(baseReportDir, self.getRelativeFilePathCallHistory())
        # Get template path
        template_name_call_history = os.path.join(os.path.dirname(os.path.abspath(__file__)), "template_call_history.html")

        # Get html_file_name
        html_file_name_phone_apps = os.path.join(baseReportDir, self.getRelativeFilePathPhoneApps())
        # Get template path
        template_name_phone_apps = os.path.join(os.path.dirname(os.path.abspath(__file__)), "template_phone_apps.html")

        with open(template_name_chats) as base_dir:
            txt = base_dir.read()
            html_ypa = bs4.BeautifulSoup(txt)

        with open(template_name_book) as base_dir:
            txt = base_dir.read()
            html_ypa_book = bs4.BeautifulSoup(txt)
        
        with open(template_name_photos) as base_dir:
            txt = base_dir.read()
            html_ypa_photos = bs4.BeautifulSoup(txt)

        with open(template_name_call_history) as base_dir:
            txt = base_dir.read()
            html_ypa_call_history = bs4.BeautifulSoup(txt)
        
        with open(template_name_phone_apps) as base_dir:
            txt = base_dir.read()
            html_ypa_phone_apps = bs4.BeautifulSoup(txt)

        # Save default photo to report folder
        repo_default_photo_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), DEFAULT_PHOTO)
        self.save_photo(Files.readAllBytes((File(repo_default_photo_path)).toPath()), baseReportDir, DEFAULT_PHOTO)

        self.add_link_to_html_report(html_ypa, "#address-book", self.getRelativeFilePathAddressBook())
        self.add_link_to_html_report(html_ypa, "#photos", self.getRelativeFilePathPhotos())
        self.add_link_to_html_report(html_ypa, "#call-history", self.getRelativeFilePathCallHistory())
        self.add_link_to_html_report(html_ypa, "#phone-apps", self.getRelativeFilePathPhoneApps())
        self.add_link_to_html_report(html_ypa_book, "#conversations", self.getRelativeFilePath())
        self.add_link_to_html_report(html_ypa_book, "#photos", self.getRelativeFilePathPhotos())
        self.add_link_to_html_report(html_ypa_book, "#call-history", self.getRelativeFilePathCallHistory())
        self.add_link_to_html_report(html_ypa_book, "#phone-apps", self.getRelativeFilePathPhoneApps())
        self.add_link_to_html_report(html_ypa_photos, "#conversations", self.getRelativeFilePath())
        self.add_link_to_html_report(html_ypa_photos, "#address-book", self.getRelativeFilePathAddressBook())
        self.add_link_to_html_report(html_ypa_photos, "#call-history", self.getRelativeFilePathCallHistory())
        self.add_link_to_html_report(html_ypa_photos, "#phone-apps", self.getRelativeFilePathPhoneApps())
        self.add_link_to_html_report(html_ypa_call_history, "#conversations", self.getRelativeFilePath())
        self.add_link_to_html_report(html_ypa_call_history, "#address-book", self.getRelativeFilePathAddressBook())
        self.add_link_to_html_report(html_ypa_call_history, "#photos", self.getRelativeFilePathPhotos())
        self.add_link_to_html_report(html_ypa_call_history, "#phone-apps", self.getRelativeFilePathPhoneApps())
        self.add_link_to_html_report(html_ypa_phone_apps, "#conversations", self.getRelativeFilePath())
        self.add_link_to_html_report(html_ypa_phone_apps, "#address-book", self.getRelativeFilePathAddressBook())
        self.add_link_to_html_report(html_ypa_phone_apps, "#photos", self.getRelativeFilePathPhotos())
        self.add_link_to_html_report(html_ypa_phone_apps, "#call-history", self.getRelativeFilePathCallHistory())
        
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
        att_media_id = skCase.getAttributeType("YPA_MEDIA_ID")
        att_pic_size = skCase.getAttributeType("YPA_PIC_SIZE")
        att_uri = skCase.getAttributeType("YPA_URI")
        att_taken_time = skCase.getAttributeType("YPA_TAKEN_TIME")
        att_orientation = skCase.getAttributeType("YPA_ORIENTATION")
        att_last_seen_time = skCase.getAttributeType("YPA_LAST_SEEN_TIME")
        att_width = skCase.getAttributeType("YPA_WIDTH")
        att_height = skCase.getAttributeType("YPA_HEIGHT")

        att_call_id = skCase.getAttributeType("YPA_CALL_ID")
        att_duration = skCase.getAttributeType("YPA_CALL_DURATION")
        att_call_type = skCase.getAttributeType("YPA_CALL_TYPE")
        att_start_time = skCase.getAttributeType("YPA_START_TIME")
        att_is_read = skCase.getAttributeType("YPA_IS_READ")

        att_package_name = skCase.getAttributeType("YPA_APP_PACKAGE_NAME")
        att_version = skCase.getAttributeType("YPA_APP_VERSION")

        # Notifications attributes
        att_na_display_name = skCase.getAttributeType("NA_APP_NAME")
        att_na_content_format = skCase.getAttributeType("NA_PAYLOAD_TYPE")

        art_count = 0
        attribute_type = self.configPanel.getAttTypeList()[self.configPanel.getSelectedAddressBookOrderIndex()]
        for artifact in sorted(art_list_contacts, key = lambda (a): a.getAttribute(attribute_type).getDisplayString()):
            username = artifact.getArtifactTypeName().split('_')[-1]
            guid = artifact.getArtifactTypeName().split('_')[-2]
            contact_id = artifact.getAttribute(att_contact_id).getDisplayString()
            address = artifact.getAttribute(att_address).getDisplayString()
            id_for_contact = address + guid
            display_name = artifact.getAttribute(att_display_name).getDisplayString()
            att_list = [address, display_name, artifact.getAttribute(att_address_type).getDisplayString(), \
                artifact.getAttribute(att_times_contacted).getDisplayString(), \
                # self.unix_to_date_string(artifact.getAttribute(att_last_contacted).getValueLong()), (disabled last_contacted - add to HTML if added back)
                self.unix_to_date_string(artifact.getAttribute(att_last_updated).getValueLong())]
            self.add_contact_modal(html_ypa, artifact, id_for_contact, username)
            # self.add_to_contact_book(html_ypa, display_name, id_for_contact, last_contacted)
            
            image_bytes = self.get_image_bytes(artifact, skCase, CONTACT_THUMBNAIL_QUERY + contact_id, display_name)
            thumbnail_path = display_name + IMAGE_EXTENSION
            if image_bytes:
                self.save_photo(image_bytes, baseReportDir, thumbnail_path)
                # self.add_photo_modal(html_ypa_photos, name, media_id, username)
            
            self.add_to_address_book(html_ypa_book, contact_id, att_list, username, thumbnail_path)
            art_count = self.increment_progress_bar(progressBar, art_count)

        dict_thread_ids = {}
        for artifact in art_list_messages:
            username = artifact.getArtifactTypeName().split('_')[-1]
            guid = artifact.getArtifactTypeName().split('_')[-2]
            # Overall chat details
            thread_id = artifact.getAttribute(att_thread_id).getValueString() + username + guid
            display_name = artifact.getAttribute(att_display_name).getValueString()
            recipients = artifact.getAttribute(att_recipient_list).getValueString()
            chat_name = recipients + " (user: " + username + ")"
            address = artifact.getAttribute(att_from_address).getValueString()
            sender = display_name + " (" + address + ")"

            # Message details
            body = artifact.getAttribute(att_body).getValueString()
            timestamp_unix = artifact.getAttribute(att_timestamp).getValueLong()
            timestamp = self.unix_to_date_string(timestamp_unix)
            if not dict_thread_ids.get(thread_id):
                # Create Chat
                dict_thread_ids[thread_id] = [1, timestamp, display_name]
                self.add_chat_to_html_report(html_ypa, chat_name, thread_id, username)
            else:
                dict_thread_ids[thread_id][0] += 1
                dict_thread_ids[thread_id][1] = timestamp
                if dict_thread_ids[thread_id][2] == NOT_AVAILABLE:
                    dict_thread_ids[thread_id][2] = display_name

            self.add_msg_to_html_report(html_ypa, thread_id, body, timestamp, sender, address, username, guid)

            art_count = self.increment_progress_bar(progressBar, art_count)

        for (t_id, t_list) in dict_thread_ids.iteritems():
            self.add_total_msgs_to_chat(html_ypa, t_id, t_list[0], t_list[1], t_list[2])

        for artifact in art_list_calls:
            username = artifact.getArtifactTypeName().split('_')[-1]
            call_id = artifact.getAttribute(att_call_id).getValueString()
            last_updated = self.unix_to_date_string(artifact.getAttribute(att_last_updated).getValueLong())
            call_start_time = self.unix_to_date_string(artifact.getAttribute(att_start_time).getValueLong())
            att_list = [artifact.getAttribute(att_display_name).getValueString(), \
                artifact.getAttribute(att_address).getValueString(), str(artifact.getAttribute(att_duration).getValueLong()), \
                artifact.getAttribute(att_call_type).getValueString(), call_start_time, \
                last_updated, artifact.getAttribute(att_is_read).getValueString()]
            self.add_to_call_history(html_ypa_call_history, call_id, att_list, username)
            
        index = 1
        for artifact in art_list_notifications:
            username = artifact.getArtifactTypeName().split('_')[-1]
            app_name = artifact.getAttribute(att_na_display_name).getValueString()
            is_xml = artifact.getAttribute(att_na_content_format).getValueString() == "Xml"
            self.add_to_phone_app_notifications(html_ypa_phone_apps, artifact, username, app_name, is_xml, index)
            index += 1

        for artifact in art_list_phone_apps:
            username = artifact.getArtifactTypeName().split('_')[-1]
            app_name = artifact.getAttribute(att_display_name).getValueString()
            package_name = artifact.getAttribute(att_package_name).getValueString()
            app_version = artifact.getAttribute(att_version).getValueString()
            play_store_link = "https://play.google.com/store/apps/details?id=" + package_name
            att_list = [app_name, package_name, app_version]
            self.add_to_phone_apps(html_ypa_phone_apps, att_list, play_store_link, username, app_name)

        progressBar.updateStatusLabel("Generating photos from BLOBs")

        for artifact in art_list_photos:
            # Get artifact info
            photo_id = artifact.getAttribute(att_photo_id).getValueString()
            media_id = artifact.getAttribute(att_media_id).getValueString()
            name = artifact.getAttribute(att_display_name).getValueString()
            last_updated = self.unix_to_date_string(artifact.getAttribute(att_last_updated).getValueLong())
            size = str(artifact.getAttribute(att_pic_size).getValueLong() / 1024)
            uri = artifact.getAttribute(att_uri).getValueString()
            taken_time = self.unix_to_date_string(artifact.getAttribute(att_taken_time).getValueLong())
            orientation = artifact.getAttribute(att_orientation).getValueString()
            last_seen_time = self.unix_to_date_string(artifact.getAttribute(att_last_seen_time).getValueLong())
            width = str(artifact.getAttribute(att_width).getValueLong())
            height = str(artifact.getAttribute(att_height).getValueLong())
            username = artifact.getArtifactTypeName().split('_')[-1]
            # guid = artifact.getArtifactTypeName().split('_')[-2]
            
            image_bytes = self.get_image_bytes(artifact, skCase, PHOTO_MEDIA_QUERY + media_id, name)
            if image_bytes is not None:
                self.save_photo(image_bytes, baseReportDir, name)
                self.add_photo_modal(html_ypa_photos, name, media_id, username)
            self.add_to_photos(html_ypa_photos, username, photo_id, media_id, name, [name, last_updated, size, media_id, uri, taken_time, orientation, last_seen_time, width, height])


        progressBar.updateStatusLabel("Saving report files")

        with open(html_file_name, "w") as outf:
            outf.write(str(html_ypa))

        with open(html_file_name_book, "w") as outf:
            outf.write(str(html_ypa_book))
        
        with open(html_file_name_photos, "w") as outf:
            outf.write(str(html_ypa_photos))

        with open(html_file_name_call_history, "w") as outf:
            outf.write(str(html_ypa_call_history))
        
        with open(html_file_name_phone_apps, "w") as outf:
            outf.write(str(html_ypa_phone_apps))
        
        Case.getCurrentCase().addReport(html_file_name, self.moduleName, "YPA Report")

        db_functions.close_db_conn(self, self.db_conn, self.db_path)

        # Elapsed time
        elapsed_time = time.time() - start_time

        self.log(Level.INFO, "YPA Report module took " + str(elapsed_time) + "s")

        progressBar.complete(ReportStatus.COMPLETE)

    def getConfigurationPanel(self):
        self.configPanel = YPA_ConfigPanel()
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

class YPA_ConfigPanel(JPanel):

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
            if att:
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