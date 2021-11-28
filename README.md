# goCabrito
Super organized and flexible script for sending phishing campaigns.

## Features 
- Sends to a single email
- Sends to lists of emails (text)
- Sends to lists emails with first, last name (csv)
- Supports attachments
- Splits emails in groups
- Delays sending emails between each group
- Support Tags to be placed and replaced in the message's body
  - Add {{name}} tag into the HTML message to be replaced with name (used with --to CSV).
  - Add {{track-click}} tag to URL in the HTML message.
  - Add {{track-open}} tag into the HTML message.
  - Add {{num}} tag to be replaced with a random phone number.
- Supports individual profiles for different campaigns to avoid mistakes and confusion.
- Supports creating database for sent emails, each email with its unique hash (useful with [getCabrito](https://github.com/KINGSABRI/getCabrito))
- Supports dry test, to run the script against your profile without sending the email to test your campaign before the launch.

## Qs & As 
### Why not use goPhish?
goPhish is a gerat choice too. But I prefer flexibility and simplicity at the same time. I used goPhish various times but at somepoint, I'm either find it overwhelming or inflexible. 

Most of the time, I don't need all these statistics, I just need a flixable way to prepare my phishing campaigns and send them. Each time I use goPhish I've to go and check the documentations about how to add a website, forward specific requests, etc. So I created [goCabrito](https://github.com/KINGSABRI/goCabrito) and [getCabrito](https://github.com/KINGSABRI/getCabrito).

getCabrito optionally generates unique URL for email tracking.
- Email Opening  tracking: Tracking Pixel 
- Email Clicking tracking

by generate a hash for each email and append it to the end of the URL or image URL and store these information along with other things that are useful for getCabrito to import and servering. **This feature is the only thing connects goCabrito with getCabrito script, so no panic!.**

### What's with the "Cabrito" thing?
It's just a name of once of my favorit resturants and the name was chosen by one of my team.


## Prerequisites 

Install gems' dependencies 
```
sudo apt-get install build-essential libsqlite3-dev
```

Install gems
```
gem install mail sqlite3
```

## Usage
```
goCabrito.rb — A simple yet flexible email sender.

Help menu:
    -s, --server HOST:PORT           SMTP server and its port.
                                        e.g. smtp.office365.com:587
    -u, --user USER                  Username to authenticate.
                                        e.g. user@domain.com
    -p, --pass PASS                  Password to authenticate
    -f, --from EMAIL                 Sender's email (mostly the same as sender email)
                                        e.g. user@domain.com
    -t, --to EMAIL|LIST|CSV          The receiver's email or a file list of receivers.
                                        e.g. user@domain.com or targets.lst or targets.csv
                                         The csv expected to be in fname,lname,email format without header.
    -c, --copy EMAIL|LIST|CSV        The CC'ed receiver's email or a file list of receivers.
    -b, --bcopy EMAIL|LIST|CSV       The BCC'ed receiver's email or a file list of receivers.
    -B, --body MSG|FILE              The mail's body string or a file contains the body (not attachements.)
                                        For click and message opening and other trackings:
                                        Add {{track-click}} tag to URL in the HTML message.
                                          eg: http://phisher.com/file.exe/{{track-click}}
                                        Add {{track-open}} tag into the HTML message.
                                          eg: <html><body><p>Hi</p>{{track-open}}</body></html>
                                        Add {{name}} tag into the HTML message to be replaced with name (used with --to CSV).
                                          eg: <html><body><p>Dear {{name}},</p></body></html>
                                        Add {{num}} tag to be replaced with a random phone number.
    -a, --attachments FILE1,FILE2    One or more files to be attached seperated by comma.
    -S, --subject TITLE              The mail subject/title.
        --no-ssl                     Do NOT use SSL connect when connect to the server (default: false).
    -g, --groups NUM                 Number of receivers to send mail to at once. (default all in one group)
    -d, --delay NUM                  The delay, in seconds, to wait after sending each group.
    -P, --profile FILE               A json file contains all the the above settings in a file
    -D, --db FILE                    Create a sqlite database file (contains emails & its tracking hashes) to be imported by 'getCabrito' server.
        --dry                        Dry test, no actual email sending.
    -h, --help                       Show this message.

Usage:
  goCabrito.rb <OPTIONS>
Examples:
  $goCabrito.rb -s smtp.office365.com:587 -u user1@domain.com -p P@ssword1 \
                       -f user1@domain.com -t targets1.csv -c targets2.lst -b targets3.lst \
                       -B msg.html -S "This's title" -a file1.docx,file2.xlsx -g 3 -d 10

  $goCabrito.rb --profile prf.json
```

### How you really use it? 
1. I create directory for each customer
2. Under the customer's directory, I create a directory for each campaign. This sub directory contains
  - The profile
  - The To, CC & BCC lists in CSV format
  - The message body in HTML format
4. I configure the profile and prepare my HTML
3. Execute the campaign profile in `dry` mode first (check the profile file `dry` value)
```
ruby goCabrito.rb -P CUSTOMER/3/camp3.json --dry
```
4. I remove the `--dry` switch and make sure the `dry` value is `false` in the config file
5. Send to a test email
6. Send to the real lists

## Troublesheooting 
### SMTP authentication issues
Nowadays, many cloud-based email vendors block SMTP authentication by default (e.g. Office365, GSuite). This of course will cause an error. To solve this, here are some steps to help you enabling AMTP authentication on different vendors.

#### Enable SMTP Auth Office 365
To globally enabling SMTP Auth, use powershell. 

- Support SSL For Linux/Nix (run pwsh as sudo required)
```powershell
$ sudo pwsh
```

- Install PSWSMan
```powershell
Install-Module -Name PSWSMan -Scope AllUsers
Install-WSMan
```

- Install ExchangeOnline Module
```powershell
Install-Module -Name ExchangeOnlineManagement
```

- Load ExchangeOnline Module
```powershell
Import-Module ExchangeOnlineManagement
```

- Connect to Office365 exchange using the main admin user, it will prompt you to enter credentials. 
```powershell
Connect-ExchangeOnline -InlineCredential
```
The above command will prompt you to enter Office365 admin's credentials 
```
  PowerShell credential request
  Enter your credentials.
  User: admin@domain.onmicrosoft.com
  Password for user admin@domain.onmicrosoft.com: **********
```

- Or us this to open web browser to enter your credentils incase of 2FA.
```powershell
Connect-ExchangeOnline -UserPrincipalName admin@pifsaudi.onmicrosoft.com 
```

- Enable SMTP AUTH Gloabally 
```powershell
Set-TransportConfig -SmtpClientAuthenticationDisabled $false
```

- To Enable for SMTP Auth for specific email
```powershell
Set-CASMailbox -Identity uuu@ccc.com -SmtpClientAuthenticationDisabled $false
Get-CASMailbox -Identity uuu@ccc.com | Format-List SmtpClientAuthenticationDisabled
```

- Confirm
```powershell
Get-TransportConfig | Format-List SmtpClientAuthenticationDisabled
```

Then follow the following steps 
1. Go to Asure portal (https://aad.portal.azure.com/) from admin panel (https://admin.microsoft.com/)
2. Select **All Services**
3. Select **Tenant Properties**
4. Click **Manage Security defaults**
5. Select **No** Under **Enable Security defaults**


- **Resources**
  * [Enable or disable SMTP AUTH | Microsoft Docs](https://docs.microsoft.com/en-us/exchange/clients-and-mobile-in-exchange-online/authenticated-client-smtp-submission)
  * [Azure Active Directory security defaults | Microsoft Docs](https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/concept-fundamentals-security-defaults)
  * [Exchange online plan 1 504 5.7.4 Unrecognized authentication type - Microsoft Q&A
  ](https://docs.microsoft.com/en-us/answers/questions/132991/exchange-online-plan-1-504-574-unrecognized-authen.html)
  * [How to set up a multifunction device or application to send email using Microsoft 365 or Office 365 | Microsoft Docs](https://docs.microsoft.com/en-us/exchange/mail-flow-best-practices/how-to-set-up-a-multifunction-device-or-application-to-send-email-using-microsoft-365-or-office-365)



### Google GSuite

- **Resources**
  - [Send email from a printer, scanner, or app - Google Workspace Admin Help](https://support.google.com/a/answer/176600?hl=en)


## Contribution 
- By fixing bugs
- By enhancing the code
- By reporting issues
- By requesting features
- By spreading the script
- By click star :)


