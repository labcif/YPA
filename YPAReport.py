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
from javax.swing import JCheckBox
from javax.swing import JLabel
from javax.swing import BoxLayout
from java.awt import Color

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

    def add_msg_to_html_report(self, html_file, thread_id, body, timestamp, from_user, address):
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
            div_msg['data-target'] = HTML_MODAL_PREFIX + address.replace('+','plus')
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

        chat = html_file.select(html_chat_id)[0]
        chat.append(div_msg)

    def add_chat_to_html_report(self, html_file, chat_id, thread_id):
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

    def add_contact_modal(self, html_file, artifact, id):
        div_modal = html_file.new_tag("div")
        div_modal['class'] = "modal fade"
        div_modal['id'] = MODAL_PREFIX + id.replace('+','plus')
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

    def add_total_msgs_to_chat(self, html_file, thread_id, num_msgs, timestamp):
        conversation = html_file.select("#" + CONVERSATION_PREFIX + thread_id)[0]
        i_total_messages = html_file.new_tag("i")
        i_total_messages.string = " - " + str(num_msgs) + " messages"

        span_time = html_file.new_tag("span")
        span_time['class'] = "time-left"
        span_time.string = timestamp

        conversation.append(i_total_messages)
        conversation.append(span_time)

    def increment_progress_bar(self, progressBar, art_count):
        if art_count % NUM_ARTIFACTS_PROGRESS == 0:
            progressBar.increment()
        return art_count + 1

    # The 'baseReportDir' object being passed in is a string with the directory that reports are being stored in.   Report should go into baseReportDir + getRelativeFilePath().
    # The 'progressBar' object is of type ReportProgressPanel.
    #   See: http://sleuthkit.org/autopsy/docs/api-docs/4.4/classorg_1_1sleuthkit_1_1autopsy_1_1report_1_1_report_progress_panel.html
    def generateReport(self, baseReportDir, progressBar):
        self.log(Level.INFO, "Starting YPA report module")

        # Count execution time
        start_time = time.time()

        # Configure progress bar for 2 tasks
        progressBar.setIndeterminate(False)
        progressBar.start()
        progressBar.updateStatusLabel("Getting artifacts...")

        skCase = Case.getCurrentCase().getSleuthkitCase()


        # Get artifact lists
        art_list_messages = skCase.getBlackboardArtifacts("YPA_MESSAGE")
        art_list_contacts = skCase.getBlackboardArtifacts("YPA_CONTACTS")
        total_artifact_count = len(art_list_messages) + len(art_list_contacts)



        if total_artifact_count == 0:
            msg = "There seem to be no YPA artifacts. Did you run the ingest module? Please cancel this report and try again after the ingest module."
            progressBar.updateStatusLabel("WARNING: " + msg)
            self.log(Level.SEVERE, msg)
            progressBar.complete(ReportStatus.ERROR)
            return

        # Dividing by ten because progress bar shouldn't be updated too frequently
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

        with open(template_name_chats) as base_dir:
            txt = base_dir.read()
            html_ypa = bs4.BeautifulSoup(txt)

        # Get Attribute types
        att_thread_id = skCase.getAttributeType("YPA_THREAD_ID")
        att_display_name = skCase.getAttributeType("YPA_DISPLAY_NAME")
        att_body = skCase.getAttributeType("YPA_BODY")
        att_timestamp = skCase.getAttributeType("YPA_TIMESTAMP")
        att_from_address = skCase.getAttributeType("YPA_FROM_ADDRESS")
        att_address = skCase.getAttributeType("YPA_ADDRESS")
        att_recipient_list = skCase.getAttributeType("YPA_RECIPIENT_LIST")

        art_count = 0
        for artifact in art_list_contacts:
            id_for_contact = artifact.getAttribute(att_address).getDisplayString()
            self.add_contact_modal(html_ypa, artifact, id_for_contact)

            art_count = self.increment_progress_bar(progressBar, art_count)

        dict_thread_ids = {}
        for artifact in art_list_messages:
            # Overall chat details
            thread_id = artifact.getAttribute(att_thread_id).getValueString()
            display_name = artifact.getAttribute(att_display_name).getValueString()
            chat_name = artifact.getAttribute(att_recipient_list).getValueString()
            address = artifact.getAttribute(att_from_address).getValueString()
            sender = display_name + " (" + address + ")"

            # Message details
            body = artifact.getAttribute(att_body).getValueString()
            timestamp = artifact.getAttribute(att_timestamp).getValueString()
            if not dict_thread_ids.get(thread_id):
                # Create Chat
                dict_thread_ids[thread_id] = [1, timestamp]
                self.add_chat_to_html_report(html_ypa, chat_name, thread_id)
            else:
                dict_thread_ids[thread_id][0] += 1
                dict_thread_ids[thread_id][1] = timestamp

            self.add_msg_to_html_report(html_ypa, thread_id, body, timestamp, sender, address)

            art_count = self.increment_progress_bar(progressBar, art_count)

        for (t_id, t_list) in dict_thread_ids.iteritems():
            self.add_total_msgs_to_chat(html_ypa, t_id, t_list[0], t_list[1])

        progressBar.updateStatusLabel("Saving report")

        with open(html_file_name, "w") as outf:
            outf.write(str(html_ypa))

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

    def initComponents(self):
        self.setLayout(BoxLayout(self, BoxLayout.Y_AXIS))

        descriptionLabel = JLabel(" YPA - Your Phone Analyzer (Report module)")
        self.add(descriptionLabel)

        skCase = Case.getCurrentCase().getSleuthkitCase()
        art_count = len(skCase.getMatchingArtifacts("JOIN blackboard_artifact_types AS types ON blackboard_artifacts.artifact_type_id = types.artifact_type_id WHERE types.type_name LIKE 'YPA_%'"))
        if art_count == 0:
            warningLabel = JLabel(" WARNING: Please run the ingest module before this report module.")
            warningLabel.setForeground(Color.RED)
            self.add(warningLabel)