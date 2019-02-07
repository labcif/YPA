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

class YourPhoneAnalyzerGeneralReportModule(GeneralReportModuleAdapter):

    moduleName = "Your Phone Analyzer Report"

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

    def add_msg_to_html_report(self, html_file, chat_id, body, time, from_user):
        div_msg = html_file.new_tag("div")

        if from_user == None:
            div_msg['class'] = "container darker"
            from_user = "You"
        else:
            div_msg['class'] = "container"

        p_sender = html_file.new_tag("p")
        p_bold_sender = html_file.new_tag("b")
        p_bold_sender.string = from_user
        p_sender.append(p_bold_sender)
        p_msg_body = html_file.new_tag("p")
        p_msg_body.string = body
        span_time = html_file.new_tag("span")
        span_time['class'] = "time-left"
        span_time.string = time

        div_msg.append(p_sender)
        div_msg.append(p_msg_body)
        div_msg.append(span_time)

        chat = html_file.select(chat_id)[0]
        chat.append(div_msg)

    def add_link_to_html_report(self, report, tag, link_to):
        link = report.select(tag)[0]
        link['href'] = link_to

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
        progressBar.updateStatusLabel("Getting files and artifacts...")

        skCase = Case.getCurrentCase().getSleuthkitCase()


        # Get artifact lists
        # art_list_reported_progs = skCase.getBlackboardArtifacts("TSK_LFA_REPORTED_PROGRAMS")
        total_artifact_count = 1

        if total_artifact_count == 0:
            msg = "There seem to be no YPA artifacts. Did you run the ingest module? Please cancel this report and try again after the ingest module."
            progressBar.updateStatusLabel("WARNING: " + msg)
            self.log(Level.SEVERE, msg)
            progressBar.complete(ReportStatus.ERROR)
            return

        # Dividing by ten because progress bar shouldn't be updated too frequently
        # So we'll update it every X artifacts (defined by a constant)
        # Plus 2 for 2 additional steps
        #max_progress = (ceil(total_artifact_count / NUM_ARTIFACTS_PROGRESS) + 2)
        #progressBar.setMaximumProgress(int(max_progress))

        # Get what reports the user wants
        # generateHTML = self.configPanel.getGenerateHTML()

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

        self.add_msg_to_html_report(html_ypa, "#collapseChat1", "Test msg", "13:37", None)
        self.add_msg_to_html_report(html_ypa, "#collapseChat1", "Test msgXD", "13:38", "User 2")

        # progressBar.updateStatusLabel("Going through all files...")

        # progressBar.updateStatusLabel("Going through Reported program artifacts now, takes some time...")

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
        # art_count = len(skCase.getMatchingArtifacts("JOIN blackboard_artifact_types AS types ON blackboard_artifacts.artifact_type_id = types.artifact_type_id WHERE types.type_name LIKE 'TSK_LFA_%'"))
        art_count = 0
        if art_count == 0:
            warningLabel = JLabel(" WARNING: Please run the ingest module before this report module.")
            warningLabel.setForeground(Color.RED)
            self.add(warningLabel)