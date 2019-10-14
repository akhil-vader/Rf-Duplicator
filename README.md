## Certificate Duplicate Finder

#### Summary <br/>
The code finds duplicate certificate json objects based on the certificate fingerprint. It tries to achieve scalability by maintaining a balance between in-memory consumption and execution runtime

#### Input and Output<br/>
The input to the code is a jsonlines file with each line corresponding to a json object.
The code writes an output file where each line corresponds to a unique fingerprint json object and its duplicates, of the format
{"fingerprint":"0C:E4:AF:24:F1:AE:B1:09:B0:42:67:CB:F8:FC:B6:AF:1C:07:D6:5B", "certificates":[A, B, C]}

#### Steps to run
* Create a virtual environment 
* Run the requirements.txt
* Make sure you have the input file in the project folder
and set the name of the input file as the value of the INPUT_FILE
* Run the python file 
* Look for the output in the "output" directory
