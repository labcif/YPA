# YourPhoneAnalyzer

*   [Installation](#windows-installation)
*   [Cite](#cite)
*   [Authors + Contacts](#authors)
*   [Test data](#test-data)
*   [Licenses](#licenses)

Autopsy plugin made to extract information from the 'Your Phone' Windows 10 App

# Windows installation

## Autopsy

1.  Download as ZIP directly from here
2.  Go to your Python Modules folder:
    1. Open Autopsy
    2. Tools > Python Plugins
3.  Unzip the downloaded ZIP inside the folder opened by Autopsy
4.  Restart or start Autopsy to compile all the libraries and files
    * If also using the Notifications plugin, you will need:
        1. Python installed to run the external script (Python 3 recommended)
        2. lxml for proper identation: `pip install lxml` (optional)
        3. win10toast for a Notification at the end of processing (optional)
5.  Open your case and run the YPA file ingest module
6.  Run the YPA Report Module with the desired options
7.  Open the report (HTML)

## Using Notification Analyzer as a Python script

You only need Python (recommended Python 3) and lxml (`pip install lxml`).

If you want a Windows Notification at the end of processing (optional): `pip install win10toast` 

You can run it as:

`python NotifAnalyzer.py -p path_to_database/wpndatabase.db -j path_to_output.json`

# Cite

If you need to cite this work, please use the following reference:

Domingues, Patricio, Miguel Frade, Luis Miguel Andrade, and João Victor Silva. "Digital forensic artifacts of the Your Phone application in Windows 10." *Digital Investigation* (2019).
https://www.sciencedirect.com/science/article/pii/S1742287619301239

# Authors

YPA was developed by Luís Miguel Andrade, João Victor Silva, Patrício Domingues, and Miguel Frade.

If you have any suggestion or find any bug, please contact us or create an issue in this repository.

**Contacts:**  

Luís Andrade - luis.m.andrade@outlook.com

João Silva - jvictor.reiss@gmail.com  

Patrício Domingues - patricio.domingues@ipleiria.pt

Miguel Frade - miguel.frade@ipleiria.pt

# Test data

If you wish to test the module before a real case, you have some dummy databases here: https://www.dropbox.com/s/t2p4q3pxe8jyaot/YourPhone_test_DB_datasource.zip?dl=0

# Licenses

This module is licensed under GPL 3.0

This module uses a modified version of mdegrazia's SQLite-Deleted-Records-Parser (https://github.com/mdegrazia/SQLite-Deleted-Records-Parser) which is licensed under GPL 3.0

This module uses the binary form of Undark (https://github.com/inflex/undark). Undark's license can be located at the file undark-LICENSE
