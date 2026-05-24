ALU Regex Data Extraction & Secure Validation

A Python program that scans realistic, production-style raw text and extracts eight types of structured data using regular expressions (regex). It also validates input for security threats and protects sensitive data in its output.
What the program does: 
The program reads input/raw-text.txt, which resembles a real email from a company. It then uses regex to find and extract eight data types:
Email addresses, phone numbers, URLs, credit cards, times 12hrs, times 24 hrs, HTML tags, Hashtags and currency.

ALU-Specific Email Validation

The program classifies emails into three special ALU categories:
ALU Official: must end with @alueducation.com
ALU Alumni :must end with @alumni.alueducation.com
ALU SI : must end with @si.alueducation.com
Each is validated carefully so only properly-formed addresses are accepted.

Security Features
The program scans for dangerous patterns before extracting anything

SQL Injection attempts
XSS / script tag injection
JavaScript protocol abuse
Inline event handlers

Validates each data type individually:
Emails with double-@, dots next to @, or SQL characters are rejected.
URLs using the javascript: pseudo-protocol are blocked.
Phone numbers that are all-zeros or known placeholders are rejected.
Credit card numbers are checked with the Luhn algorithm, a real-world mathematical test used by every card processor.

Masks sensitive data in output:
Credit card numbers are shown as **** **** **** 1234 (only last 4 digits).
Email addresses are shown as j***@alueducation.com.
This is done for proctection.

The program then saves the results of the validations and extraction to an output json file.

How to run the program 
Run the program in Python 3.7 or higher
It will print out a smmary of the results in your terminal
Then save the results to output/sample-output.json
