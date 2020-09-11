import os
from org.sleuthkit.autopsy.datamodel import ContentUtils
from java.sql import DriverManager, SQLException
from java.io import File
from java.lang import Class
from java.util.logging import Level
from org.sqlite import SQLiteConfig, SQLiteOpenMode
from org.sqlite.SQLiteConfig import JournalMode

def execute_query(self, query, db_conn, db_name = "UNKNOWN"):
    db_name = "[" + db_name + "] "
    try:
        stmt = db_conn.createStatement()
        result = stmt.executeQuery(query)
        self.log(Level.INFO, db_name + "Executed query: " + query)
        return result, stmt
    except SQLException as e:
        self.log(Level.SEVERE, db_name + "Failed to execute query: " + query + ", due to " + str(e))
    return None

def execute_statement(self, query, db_conn, db_name = "UNKNOWN"):
    db_name = "[" + db_name + "] "
    try:
        stmt = db_conn.prepareStatement(query)
        stmt.execute()
        self.log(Level.INFO, db_name + "Executed statement: " + query)
        return stmt
    except SQLException as e:
        self.log(Level.SEVERE, db_name + "Failed to execute statement: " + query + ", due to " + str(e))

def create_db_conn(self, file, temp_dir = None):
    if not temp_dir:
        temp_dir = self.temp_dir
    db_path = os.path.join(temp_dir, str(file.getName()))
    ContentUtils.writeToFile(file, File(db_path))
    try:
        Class.forName("org.sqlite.JDBC").newInstance()
        config = SQLiteConfig()
        config.setEncoding(SQLiteConfig.Encoding.UTF8)
        # config.setJournalMode(JournalMode.WAL)
        # config.setReadOnly(True)
        db_conn = DriverManager.getConnection("jdbc:sqlite:%s" % db_path, config.toProperties())
        # execute_query(self, "PRAGMA wal_checkpoint", db_conn, file.getName())
        return db_conn, db_path
    except Exception as e:
        self.log(Level.SEVERE, "Could not create database connection for " +
                    db_path + " (" + str(e) + ")")
    return None, db_path

def close_db_conn(self, db_conn, db_path):
    db_conn.close()
    try:
        os.remove(db_path)
    except (Exception, OSError):
        self.log(Level.SEVERE, "Error deleting temporary DB: " + db_path)