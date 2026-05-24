import re   
import json  
import os    

# step 1: read the input file

base_folder = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# build the path to the input file
input_path = os.path.join(base_folder, "input", "raw-text.txt")
# build the path to the output file
output_path = os.path.join(base_folder, "output", "sample-output.json")
#open and read the file into a variable called text
input_file = open(input_path, "r")
text = input_file.read()
input_file.close()

print("File loaded successfully!")
print("")

#step2 : Security check
print(" SECURITY SCAN ")
security_log = [] #this list will have any security threats we find

#check 1 : SQL 
# to check if there are no database commands in the text
sql_pattern = r"(--|')\s*(or|select|drop|union)\b"
sql_matches = re.findall(sql_pattern, text, re.IGNORECASE)

if len(sql_matches) > 0:
    print("  WARNING: SQL Injection attempt found and blocked!")
    security_log.append({"threat": "SQL Injection", "count": len(sql_matches)})

# check 2 : malicious codes (XSS)
xss_pattern = r"<script[\s\S]*?>"
xss_matches = re.findall(xss_pattern, text, re.IGNORECASE)

if len(xss_matches) > 0:
    print(" WARNING: XSS script tag found and blocked!")
    security_log.append({"threat": "XSS / Script Tag", "count": len(xss_matches)})

# check 3: JavaScript in URLs 
js_pattern = r"javascript\s*:"
js_matches = re.findall(js_pattern, text, re.IGNORECASE)

if len(js_matches) > 0:
    print("WARNING: JavaScript injection in URL found and blocked!")
    security_log.append({"threat": "JS Protocol Injection", "count": len(js_matches)})

# If nothing bad was found, say so
if len(security_log) == 0:
    print("  No threats found. Input looks clean.")

print("")

# Step 3 : Helper functions
def mask_card(card_number):
    #remove spaces and dashes so we only have the digits
    clean = ""
    for character in card_number:
        if character != " " and character != "-":
            clean = clean + character

    #take only the last 4 digits
    last_four = clean[-4:]

    #return a masked version
    return "**** **** **** " + last_four

# Hide the a part of the email in the output
def mask_email(email):
    # Split the email at the @ symbol to get two parts
    parts = email.split("@")
    local_part = parts[0]   #everything before @
    domain_part = parts[1]  #everything after @

    #the masked version
    masked = local_part[0] + "***@" + domain_part
    return masked

# Chek if the credit card number is valid
def luhn_ok(card_number):
    #removing all non-digit characaters to only have numbers
    digits = ""
    for character in card_number:
        if character.isdigit():
            digits = digits + character

    #check if the card has btn 13-19 numbers
    if len(digits) < 13 or len(digits) > 19:
        return False
    # applying the luhn formula
    total = 0
    reverse_digits = digits[::-1]  # reverse the string so we start from the right

    for i in range(len(reverse_digits)):
        n = int(reverse_digits[i])

        #every second position gets doubled
        if i % 2 == 1:
            n = n * 2
            #if the doubled number is greater than 9, subtract 9
            if n > 9:
                n = n - 9

        total = total + n

    # If the total divides evenly by 10, the card is valid
    if total % 10 == 0:
        return True
    else:
        return False


# check for email validity
def email_ok(email):
    # Reject if the email contains characters used in SQL attacks
    if "'" in email:
        return False
    if "--" in email:
        return False
    if "<" in email:
        return False
    if ">" in email:
        return False

    # splitting at @ to get the domain
    parts = email.split("@")
    domain = parts[-1]

    if domain.startswith("."): #check if the email starts witha dot
        return False
    if ".." in email: #chek if the email has two dots anywhhere
        return False

    return True

#step 4 : exract the emails
# Pattern explanation:
# [a-zA-Z0-9._%+-]+ :one or more allowed characters before the @
# @ : the @ symbol itself
# [a-zA-Z0-9.-]+ :one or more characters for the domain name
#\. :check for the dot itself
#[a-zA-Z]{2,} :the top-level domain like com, org, rw (at least 2 letters)
email_pattern = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"

all_emails = re.findall(email_pattern, text)

#separate emails into valid and rejected
valid_emails = []
rejected_emails = []

for email in all_emails:
    if email_ok(email) == True:
        valid_emails.append(email)
    else:
        rejected_emails.append(email)

# sort fro ALU categoried
alu_official = []
alu_alumni = []
alu_si = []
other_emails = []

for email in valid_emails:
    if email.endswith("@alumni.alueducation.com"):
        alu_alumni.append(mask_email(email))
    elif email.endswith("@si.alueducation.com"):
        alu_si.append(mask_email(email))
    elif email.endswith("@alueducation.com"):
        alu_official.append(mask_email(email))
    else:
        other_emails.append(mask_email(email))

#Step 5 : extract URLs
# Pattern explanation:
#(https?|ftp): matches http, https, or ftp
#://:matches the exact characters ://
# [^\s<>"']+ :matches everything after that EXCEPT spaces, < > " '
url_pattern = r"(https?|ftp)://[^\s<>\"']+"

all_urls = []
valid_urls = []
blocked_urls = []
for match in re.finditer(url_pattern, text):
    url = match.group()
    all_urls.append(url)

#check each URL for the javascript: trick
for url in all_urls:
    if "javascript:" in url.lower():
        blocked_urls.append(url)
    else:
        valid_urls.append(url)

#Step 6 : extract phone numbers
#regex pattern explanation:
# Format 1: +250 788 441 230
#   \+ :matches the + sign
#   \d{1,3} :matches 1 to 3 digits (the country code)
#   [\s-]? :optional space or dash
#   (\(\d{1,4}\))? :optional area code in brackets like (250)
#   [\s-]? :optional space or dash
#   \d[\d\s-]{5,12}\d :the local number (at least 7 digits with optional spaces/dashes)
#
# Format 2: (250) 783-100-200
#   \(\d{1,4}\):the area code in brackets
#   [\s-]:a space or dash after the bracket
#   \d[\d\s-]{5,12}\d:the rest of the number
#
# Format 3: 000-000-0000 
#   \d{3}[-.] :three digits then a dash or dot
#   \d{3}[-.] :three more digits then a dash or dot
#   \d{4} :four final digits

phone_pattern = (
    r"\+\d{1,3}[\s-]?(\(\d{1,4}\))?[\s-]?\d[\d\s-]{5,12}\d"
    r"|\(\d{1,4}\)[\s-]\d[\d\s-]{5,12}\d"
    r"|\d{3}[-.]\d{3}[-.]\d{4}"
)

all_phones = []
valid_phones = []
bad_phones = []

for match in re.finditer(phone_pattern, text):
    phone = match.group().strip()
    all_phones.append(phone)

# Check each phone number for known placeholder/fake numbers
for phone in all_phones:
    # Remove everything except digits to check the raw number
    digits_only = ""
    for character in phone:
        if character.isdigit():
            digits_only = digits_only + character
    if digits_only == "0000000000":
        bad_phones.append(phone)
    else:
        valid_phones.append(phone)

# Step 7 :extract credit card numbers
# regex pattern explanation:
#   \b:word boundary — makes sure we don't grab numbers inside larger text
#   \d{4}: exactly 4 digits
#   [\s-]? :optional space or dash between groups
#   \d{4,6} :4 to 6 digits (handles Amex which has different grouping)
#   [\s-]? :optional space or dash
#   \d{4,6} :another group of 4 to 6 digits
#   [\s-]? :optional space or dash
#   \d{0,5} :optional final group (some cards end here, some don't)
#   \b :end word boundary
card_pattern = r"\b\d{4}[\s-]?\d{4,6}[\s-]?\d{4,6}[\s-]?\d{0,5}\b"

all_cards = re.findall(card_pattern, text)
valid_cards = []
bad_cards = []

for card in all_cards:
    if luhn_ok(card) == True:
        #card passed and saved as a maked version
        valid_cards.append(mask_card(card))
    else:
        # Card failed 
        bad_cards.append(mask_card(card) + " (failed Luhn check)")

#Step 8 : extract times in both 12-hour and 24-hour formats
#pattern explanation:
# 12-hour format pattern
# \b:word boundary
# (1[0-2]|0?[1-9]) :hours 1 to 12 (with optional leading zero)
# : the colon
# [0-5]\d :minutes from 00 to 59
# \s* :optional space between the time and AM/PM
# [AaPp][Mm] :AM or PM in any case (am, Am, AM, pm, Pm, PM)
# \b :word boundary
time_12h_pattern = r"\b(1[0-2]|0?[1-9]):[0-5]\d\s*[AaPp][Mm]\b"

# 24-hour format pattern
# pttern explanation:
#\b :word boundary
#([01]\d|2[0-3]):hours from 00 to 23
#: the colon
#0-5]\d :minutes from 00 to 59
#\b : word boundary
time_24h_pattern = r"\b([01]\d|2[0-3]):[0-5]\d\b"

times_12h = []
times_24h = []

for match in re.finditer(time_12h_pattern, text):
    times_12h.append(match.group())

for match in re.finditer(time_24h_pattern, text):
    times_24h.append(match.group())

#Step 9 :extract HTML tags and check for dangerous ones
#tag pattern explanation:
# < :opening angle bracket
# /? :optional / for closing tags
# [a-zA-Z] :tag name must start with a letter
# [a-zA-Z0-9]* :rest of the tag name (letters and digits)
# (?:\s[^>]*)? :optional attributes
# \s*:optional whitespace before closing
# /?>:optional self-closing / then the closing >
tag_pattern = r"</?[a-zA-Z][a-zA-Z0-9]*(?:\s[^>]*)?\s*/?>"

all_tags = re.findall(tag_pattern, text)
safe_tags = []
bad_tags = []

for tag in all_tags:
    # check the validity of the tags
    if re.search(r"on\w+=", tag, re.IGNORECASE):
        bad_tags.append(tag)
    elif re.search(r"javascript:", tag, re.IGNORECASE):
        bad_tags.append(tag)
    elif re.search(r"<script", tag, re.IGNORECASE):
        bad_tags.append(tag)
    else:
        safe_tags.append(tag)

#Step 10 : extract hashtags
#regex pattern explanation:
# # :the hashtag symbol
# [a-zA-Z] :must start with a letter (not a number or symbol)
# [a-zA-Z0-9_]* :followed by any letters, digits, or underscores
hashtag_pattern = r"#[a-zA-Z][a-zA-Z0-9_]*"
hashtags = re.findall(hashtag_pattern, text)
 
#step 11 : extract currency amounts
#regex pattern explanation:
# [$£€] :one of the three currency symbols: dollar, pound, euro
# \d{1,3} :one to three digits (e.g. 25 or 2)
# (,\d{3})* :optional groups of comma + 3 digits for thousands (e.g. ,500)
# (\.\d{2})? :optional decimal point followed by exactly 2 digits (e.g. .00)
currency_pattern = r"[$£€]\d{1,3}(,\d{3})*(\.\d{2})?"

currency = []

for match in re.finditer(currency_pattern, text):
    currency.append(match.group())

#step 12: put toether all esults

results = {
    "security_threats": security_log,
    "emails": {
        "alu_official": alu_official,
        "alu_alumni": alu_alumni,
        "alu_si": alu_si,
        "other_valid": other_emails,
        "rejected": rejected_emails
    },
    "urls": {
        "valid": valid_urls,
        "blocked": blocked_urls
    },
    "phones": {
        "valid": valid_phones,
        "invalid": bad_phones
    },
    "credit_cards": {
        "valid_masked": valid_cards,
        "invalid_masked": bad_cards
    },
    "times": {
        "12_hour": times_12h,
        "24_hour": times_24h
    },
    "html_tags": {
        "safe": safe_tags,
        "unsafe": bad_tags
    },
    "hashtags": hashtags,
    "currency": currency
}

#step 13 :print the results 

for section in results:
    print( section.upper(),":")
    data = results[section]
    #if the value is a plain list, just print it
    if isinstance(data, list):
        print("  ", data)
    #if the value is a dictionary, print each key and its list
    else:
        for key in data:
            print("  " + key + ":", data[key])

    print("")

#step 14 : save the results to the JSON file
#create the output folder if it does not exist yet
os.makedirs(os.path.dirname(output_path), exist_ok=True)

#open the output file and write our results into it
output_file = open(output_path, "w")
json.dump(results, output_file, indent=2)
output_file.close()

print("Done! Results saved to:", output_path)