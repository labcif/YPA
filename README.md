# YourPhoneAnalyzer

*   [Installation](#windows-installation)
*   [Authors + Contacts](#authors)
*   [Test data](#test-data)
*   [Licenses](#licenses)

Autopsy plugin made to extract information from the 'Your Phone' Windows 10 App

# Windows installation

1.  Download as ZIP directly from here
2.  Go to your Python Modules folder:
    1. Open Autopsy
    2. Tools > Python Plugins
3.  Unzip the downloaded ZIP inside the folder opened by Autopsy
4.  Restart or start Autopsy to compile all the libraries and files
5.  Open your case and run the YPA file ingest module
6.  Run the YPA Report Module with the desired options
7.  Open the report (HTML)

# Authors

YPA was developed by Luís Miguel Andrade, João Victor Silva, Patrício Domingues, and Miguel Frade.

If you have any suggestion or find any bug, please contact us or create an issue in this repository.

**Contacts:**  

Luís Andrade - luis.andrade@ipleiria.pt

João Silva - jvictor.reiss@gmail.com  

Patrício Domingues - patricio.domingues@ipleiria.pt

Miguel Frade - miguel.frade@ipleiria.pt

# Test data

If you wish to test the module before a real case, you have some dummy databases here: https://www.dropbox.com/s/t2p4q3pxe8jyaot/YourPhone_test_DB_datasource.zip?dl=0

# Licenses

This module is licensed under GPL 3.0

This module uses a modified version of mdegrazia's SQLite-Deleted-Records-Parser (https://github.com/mdegrazia/SQLite-Deleted-Records-Parser) which is licensed under GPL 3.0

This module uses the binary form of Undark (https://github.com/inflex/undark). Undark's license can be located at the file undark-LICENSE
