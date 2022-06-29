# hash2csvbatch
Script recognizing hashes, and after that gathering information about them

# Usage

## Normal search
To start normal search (not requring api keys, etc.) in malware baazar database:    
   ```py hash2csvbatch.py -p "path_to_folder_containing_summary (without trailing slash)" ```, \
or:\
   ```py hash2csvbatch.py --path "path_to_folder_containing_summary (without trailing slash)" ```

Example:\
   ```py hash2csvbatch.py -p "C:\test"```

## VirusTotal search
Search in virustotal db using their v3 api. This search look only through avast av entries:
```py hash2csvbatch.py -f secondary or py hash2csvbatch.py -- mode secondary```

Search in virustotal db using their v3 api. This search use first available guess of threat/malware.
```py hash2csvbatch.py -f third or py hash2csvbatch.py -- mode third```

## Unify datetime format

```py hash2csvbatch.py -f datetime_normalization or py hash2csvbatch.py -- mode datetime_normalization ```



