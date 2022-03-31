# hash2csvbatch
Script recognizing hashes, and after that gathering information about them

USAGE:
1. To start normal search (not requring api keys, etc.) in malware baazar database.

a) py hash2csvbatch.py -p "path_to_folder_containing_summary (without trailing slash)" or py hash2csvbatch.py --path "path_to_folder_containing_summary (without trailing slash)"
example:
py hash2csvbatch.py -p "C:\test"

2. Search in virustotal db using their v3 api. This search look only through avast av entries.

a) py hash2csvbatch.py -f secondary or py hash2csvbatch.py -- mode secondary

3. Search in virustotal db using their v3 api. This search use first available guess of threat/malware.

a) py hash2csvbatch.py -f third or py hash2csvbatch.py -- mode third

4. Unify datetime format:

a) py hash2csvbatch.py -f datetime_normalization or py hash2csvbatch.py -- mode datetime_normalization 



