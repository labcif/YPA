import os
from org.sleuthkit.autopsy.datamodel import ContentUtils
from java.sql import DriverManager, SQLException
from java.io import File
from java.lang import Class
from java.util.logging import Level
from org.sqlite import SQLiteConfig, SQLiteOpenMode
from org.sqlite.SQLiteConfig import JournalMode

def execute_query(self,  query, db_conn):
    try:
        return db_conn.createStatement().executeQuery(query)
    except SQLException as e:
        self.log(Level.SEVERE, "Failed to execute query: " + query + ", due to " + str(e))
    return

def create_db_conn(self, file, temp_dir = None):
    if not temp_dir:
        temp_dir = self.temp_dir
    dbPath = os.path.join(temp_dir , str(file.getName()))
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

def close_db_conn(self,  db_conn, db_path):
    db_conn.close()
    try:
        os.remove(db_path)
    except (Exception, OSError) as e:
        self.log(Level.SEVERE, "Error deleting temporary DB: " + str(e))