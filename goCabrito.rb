#!/usr/bin/env ruby
#
# --- profile.json ---
# {
#   "server":  "smtp.office365.com:587",
#   "user":    "sender@example.com",
#   "pass":    "P@ssw0rd!",
#   "no_ssl":  false, 
#   "from":    "sender@example.com",
#   "to":      "/full/path/to/goCabrito/targets1.csv",
#   "copy":    "/full/path/to/goCabrito/targets2.csv",
#   "bcopy":   "/full/path/to/goCabrito/targets3.csv",
#   "subject": "Test profile",
#   "body":    "/full/path/to/goCabrito/msg.html",
#   "attachments": [
#     "/home/KING/Code/Ruby/NETWORK/goCabrito/abl/campaigns/test/attachme.txt",
#     "/home/KING/Code/Ruby/NETWORK/goCabrito/abl/campaigns/test/attachme2.xlsx"
#   ],
#   "groups":  "0",
#   "delay":   "0",
#   "dry":     true
# }
# -----------------
# Usage:
# $ ruby goCabrito-attach.rb --profile prf.json
# $ ruby goCabrito-attach.rb -s smtp.office365.com:587 -u user1@domain.com -p P@ssword1 \
#                            -f user1@domain.com -t targets1.csv -c targets2.lst -b targets3.lst \
#                            -B msg.html -S "This's title" -a file1.docx,file2.xlsx -g 3 -d 10
# 
# apt-get install sqlite3 libsqlite3-dev sqlite3
# 
# Check for mail spoofing
#  https://sendgrid.com/
# 
# http://localhost:8181/images/AblLogo.png//vT2upzQzXPu8pUW/ct/61282606f5e4cb3202bd129ce707a771a5dbde05
# http://localhost:8181/https://google.com/vT2upzQzXPu8pUW/ct/61282606f5e4cb3202bd129ce707a771a5dbde05

class String
  def red;          colorize(self, "\e[1m\e[31m");                end
  def green;        colorize(self, "\e[1m\e[32m");                end
  def dark_green;   colorize(self, "\e[32m");                     end
  def yellow;       colorize(self, "\e[1m\e[33m");                end
  def blue;         colorize(self, "\e[1m\e[34m");                end
  def dark_blue;    colorize(self, "\e[34m");                     end
  def purple;       colorize(self, "\e[35m");                     end
  def dark_purple;  colorize(self, "\e[1;35m");                   end
  def cyan;         colorize(self, "\e[1;36m");                   end
  def dark_cyan;    colorize(self, "\e[36m");                     end
  def pure;         colorize(self, "\e[0m\e[28m");                end
  def underline;    colorize(self, "\e[4m");                      end
  def bold;         colorize(self, "\e[1m");                      end
  def info;         colorize(self, "[" + "ℹ".blue + "] ");        end
  def info_h3;      colorize(self, " " + "|".blue + "  ");        end
  def error;        colorize(self, "[" + "x".red + "] ");         end
  def warn;         colorize(self, "[" + "!".bold.yellow + "] "); end
  def warn_h3;      colorize(self, " " + "|".yellow + "  ");      end
  def step_h1;      colorize(self, "[" + "+".green + "] ");       end
  def step_h2;      colorize(self, " " + "|".green + "  ");       end
  def step_h3;      colorize(self, " " + "|".green + "  ");       end
  def step_done;    colorize(self, " " + "|✓".green + "  ");      end
  def done;         colorize(self, "[" + "+".green + "] ");       end
  def colorize(text, color_code) "#{color_code}#{text}\e[0m"      end
end


require 'bundler/inline'
begin
  puts "Checking dependencies:".info
  require 'csv'
  require 'mail'
  require 'json'
  require 'sqlite3'  
  require 'ostruct'
  require 'optparse'
  require 'securerandom'
rescue Exception
  puts "Found missing dependencies:".warn
  puts "Installing dependencies..".warn_h3
  gemfile do 
    source 'https://rubygems.org'
    gem 'csv',          require: 'csv'
    gem 'mail',         require: 'mail'
    gem 'json',         require: 'json'
    gem 'sqlite3',      require: 'sqlite3'
    gem 'optparse',     require: true
    gem 'ostruct',      require: true
    gem 'securerandom', require: true
  end
  puts "Install completed.".done
end
puts "".info_h3
puts "".info_h3

# 
# Global Options
# 
$opt = OpenStruct.new(
  server: nil, user: nil, pass: nil, no_ssl: false,
  from: nil,  to: nil, copy: nil, bcopy: nil, body: nil, subject: nil,
  groups: 1, delay: 0, profile: nil, topen: false, tclick: false,
  str: false, file: false, csv: false, html: false, attachments: [],
  dry: false, help: false, db: nil
)
@mail = nil

# Validate CSV format
# https://stackoverflow.com/questions/14693929/ruby-how-can-i-detect-intelligently-guess-the-delimiter-used-in-a-csv-file
# 
def valid_csv?(path)
  common_delimiters = ['","', "\"\t\"", '"|"', '";"'].freeze
  first_line = File.open(path).first
  return false unless first_line

  sniff = {}
  common_delimiters.each do |delim| 
    sniff[delim] = first_line.count(delim)
  end
  sniff = sniff.sort { |a,b| b[1]<=>a[1] }
  $opt.csv = !sniff.collect(&:last).reduce(:+).zero?
end

def valid_html?(path)
  content = File.read(path)
  return false unless content
  tags = content.scan(/<.*?>/)
  $opt.html = !tags.size.zero?
end

# Check if the given arguement is a string file (list or CSV file).
def read_arg(val)
  file_path = File.absolute_path(val.to_s)
  if File.file?(file_path)
    if valid_html?(file_path)
      # puts "HTML file detected: #{file_path}".info_h3
      return File.read(file_path)
    elsif valid_csv?(file_path)
      # puts "CSV file detected : #{file_path}".info_h3
      return CSV.read(file_path)
    else
      # puts "Normal file detected: #{file_path}".info_h3
      $opt.file = true
      return File.read(file_path)
    end    
  else
    # puts "String detected   : '#{val}'".info_h3
    $opt.str = true
    val
  end
rescue Exception => e 
  # puts "Error in detecting string/file".error
  puts e.full_message
  exit!
end

def str2list(str)
  return if str.nil?
  str.each_line(chomp: true)
                .map(&:strip)
                .reject(&:nil?)
                .reject(&:empty?)
end

def create_database(db_name)
  fname = File.basename(db_name, File.extname(db_name))  + '.db'
  fpath = File.dirname(db_name)
  db_name = File.join(fpath, fname)
  puts "Creating '#{db_name}' database".step_h1
  @db_sql = SQLite3::Database.new(db_name)
  if @db_sql.table_info("targets").empty?
    @db_sql.execute <<-SQL
    CREATE TABLE IF NOT EXISTS targets (
        target_id   INTEGER PRIMARY KEY,
        email       TEXT,
        hash        TEXT,
        session     TEXT,
        click_at    TEXT,
        open_at     TEXT,
        user_agent  TEXT,
        ip_addr     TEXT,
        click_count INTEGER,
        open_count  INTEGER,
        UNIQUE(email, hash)
      );
    SQL
    
    @db_sql.execute <<-SQL
      CREATE TABLE IF NOT EXISTS loots (
        loot_id     INTEGER PRIMARY KEY,
        loot        blob,
        target_id   INTEGER,
        FOREIGN KEY (target_id)
          REFERENCES targets (target_id)
          ON UPDATE CASCADE
          ON DELETE CASCADE
      );
    SQL
  
    puts "Database '#{db_name}' created.".step_done
  end
end

def store_email(email, hash)
  @db_sql.execute("INSERT OR IGNORE INTO targets 
    (email, hash, session, click_at, open_at, user_agent, ip_addr, click_count, open_count)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", 
    [email, hash, nil, nil, nil, nil, nil, 0, 0])
end

def setup_mail(server, port, user, pass, ssl)
  @mail = Mail.new do
    delivery_method :smtp, 
    address:              server,
    port:                 port.to_i,
    domain:               user.split('@').last,
    user_name:            user,
    password:             pass,
    authentication:       'login',
    enable_starttls_auto: ssl
  end
rescue Exception => e 
  puts "#{e.full_message}".error
end

def build_message(message)
  @mail.html_part do 
    content_type 'text/html; charset=UTF-8'
    body message 
  end
end

def rnd_str
  SecureRandom.alphanumeric(rand(5..20))
end

# Find and replace all kind of tags within the message body
#  available tags:
#   {{track-click}}  
#      Appends /RANDOM-STRING/ct/SHA1(email) to the URL. Eg. http://localhost:8181/login/vT2upzQzXPu8pUW/ct/251d01e26c5aada16a6d713b4de70bb89ff3298f
#   {{track-open}}
#      Appends /RANDOM-STRING/ot/SHA1(email) to the URL. Eg. http://localhost:8181/logon.png/vT2upzQzXPu8pUW/ot/251d01e26c5aada16a6d713b4de70bb89ff3298f
#   {{name}}
#   {{num}}
#      Generates 7 random digits 
# 
def track(msg, email, name = "")
  hash    = Digest::SHA1.hexdigest(email)
  rnd_num = rand.to_s[2..8]

  store_email(email, hash) unless $opt.db.nil? 
  msg  = msg.gsub("{{track-click}}","/#{rnd_str}/ct/#{hash}")
            .gsub("{{track-open}}", "/#{rnd_str}/ot/#{hash}")
            .gsub("{{name}}", name.to_s)
            .gsub("{{num}}", rnd_num)
end

def validate_email(email)
  if email.to_s.include?("@")
    email
  else
    puts "Invalid email format: #{email}".error
    exit!
  end
end

def print_mail_errors
  puts "[!] bounced: #{@mail.bounced?}"                if @mail.bounced?
  puts "[!] final_recipient: #{@mail.final_recipient}" if @mail.final_recipient
  puts "[!] action: #{@mail.action}"                   if @mail.action
  puts "[!] error_status: #{@mail.error_status}"       if @mail.error_status
  puts "[!] diagnostic_code: #{@mail.diagnostic_code}" if @mail.diagnostic_code
  puts "[!] retryable: #{@mail.retryable?}"            if @mail.retryable?
end

option_parser = OptionParser.new do |opts|
  opts.banner = "#{File.basename(__FILE__)} — A simple yet flexible email sender."
  opts.separator ""
  opts.separator "Help menu:"

  opts.on("-s", "--server HOST:PORT", "SMTP server and its port.", "\te.g. smtp.office365.com:587") do |o|
    $opt.server = o
  end

  opts.on("-u", "--user USER", "Username to authenticate.", "\te.g. user@domain.com") do |o|
    $opt.user = validate_email(o)
  end

  opts.on("-p", "--pass PASS", "Password to authenticate") do |o|
    $opt.pass = o
  end

  opts.on("-f", "--from EMAIL", "Sender's email (mostly the same as sender email)", "\te.g. user@domain.com") do |o|
    $opt.from = validate_email(o)
  end

  opts.on("-t", "--to EMAIL|LIST|CSV", "The receiver's email or a file list of receivers.", 
                                       "\te.g. user@domain.com or targets.lst or targets.csv",
                                       "\t The csv expected to be in #{"fname,lname,email".dark_cyan} format without header."
                                       ) do |o|
    $opt.to = o  # we will validate the emails later
  end

  opts.on("-c", "--copy EMAIL|LIST|CSV", "The CC'ed receiver's email or a file list of receivers.") do |o|
    $opt.copy = o
  end

  opts.on("-b", "--bcopy EMAIL|LIST|CSV", "The BCC'ed receiver's email or a file list of receivers.") do |o|
    $opt.bcopy = o
  end

  opts.on("-B", "--body MSG|FILE", "The mail's body string or a file contains the body (not attachements.)",
                                   "\tFor click and message opening and other trackings:",
                                   "\tAdd #{"{{track-click}}".dark_cyan} tag to URL in the HTML message.",
                                   "\t  eg: http://phisher.com/file.exe/{{track-click}}",
                                   "\tAdd #{"{{track-open}}".dark_cyan} tag into the HTML message.",
                                   "\t  eg: <html><body><p>Hi</p>{{track-open}}</body></html>",
                                   "\tAdd #{"{{name}}".dark_cyan} tag into the HTML message to be replaced with name (used with --to CSV).",
                                   "\t  eg: <html><body><p>Dear {{name}},</p></body></html>",
                                   "\tAdd #{"{{num}}".dark_cyan} tag to URL in the HTML message to be replaced with a random phone number.",
  ) do |o|
    $opt.body = o
  end

  opts.on("-a", "--attachments FILE1,FILE2", Array, "One or more files to be attached seperated by comma.") do |o|
    $opt.attachments = o
  end

  opts.on("-S", "--subject TITLE", "The mail subject/title.") do |o|
    $opt.subject = o
  end

  opts.on("--no-ssl", "Do NOT use SSL connect when connect to the server (default: false).") do |o|
    $opt.no_ssl = o
  end

  opts.on("-g", "--groups NUM", "Number of receivers to send mail to at once. (default all in one group)") do |o|
    $opt.groups = o
  end

  opts.on("-d", "--delay NUM", "The delay, in seconds, to wait after sending each group.") do |o|
    $opt.delay = o
  end

  opts.on("-P", "--profile FILE", "A json file contains all the the above settings in a file") do |o|
    $opt.profile = o
  end

  opts.on("-D", "--db FILE", "Create a sqlite database file (contains emails & its tracking hashes) to be imported by 'getCabrito' server.") do |o|
    $opt.db = o
  end

  opts.on("--dry", "Dry test, no actual email sending.") do |o|
    $opt.dry = o
  end

  opts.on("-h", "--help", "Show this message.") do
    $opt.help = true
    puts opts
    exit!
  end

  opts.on_tail "\nUsage:\n" + "  #{File.basename(__FILE__)} <OPTIONS>"
  opts.on_tail "Examples:"
  # opts.on_tail %{  $#{File.basename(__FILE__)} -s smtp.office365.com:587 -u user1@domain.com -p P@ssword1 -f user1@domain.com -t targets1.csv -c targets2.lst -b targets3.lst -B msg.html -S "This's title" -g 3 -d 10\n}
  opts.on_tail %{  $#{File.basename(__FILE__)} -s smtp.office365.com:587 -u user1@domain.com -p P@ssword1 \\
                       -f user1@domain.com -t targets1.csv -c targets2.lst -b targets3.lst \\
                       -B msg.html -S "This's title" -a file1.docx,file2.xlsx -g 3 -d 10\n\n}
  opts.on_tail %{  $#{File.basename(__FILE__)} --profile prf.json\n\n}
end

begin
  option_parser.parse!(ARGV)

  create_database($opt.db) unless $opt.help || $opt.db.nil?

  if $opt.profile
    prf = JSON.parse(File.read($opt.profile), symbolize_names: true)
    $opt.server      = prf[:server]
    $opt.user        = prf[:user]
    $opt.no_ssl      = prf[:no_ssl]
    $opt.pass        = prf[:pass]
    $opt.from        = prf[:from]
    $opt.to          = prf[:to]
    $opt.copy        = prf[:copy]
    $opt.bcopy       = prf[:bcopy]
    $opt.body        = prf[:body]    
    $opt.subject     = prf[:subject]
    $opt.attachments = [prf[:attachments]].compact.flatten
    $opt.groups      = prf[:groups].to_i
    $opt.delay       = prf[:delay].to_i
    $opt.dry         = $opt.dry || prf[:dry]
  end

  if $opt.from.nil? && !$opt.user.nil?
    puts "-f/--from provided, will use the user as sender.".warn
    $opt.from = $opt.user
  end

  mandatory_opts = {
    "-s/--server"  => $opt.server,
    "-u/--user"    => $opt.user,
    "-p/--pass"    => $opt.pass,
    "-f/--from"    => $opt.from,
    "-t/--to"      => $opt.to,
    "-b/--body"    => $opt.body,
    "-S/--subject" => $opt.subject
  }
  missing = []
  abort   = false 
  mandatory_opts.each do |key, val|
    if val.nil? || val.empty?
      missing << key
      abort = true
    end
  end
  unless missing.empty?
    puts "Missing mandatory options: ".error
    puts missing.compact.join(", ")
    exit! 
  end

  # if (
  #       $opt.server || $opt.user || $opt.pass ||
  #       $opt.from   || $opt.to   || $opt.body || $opt.subject
  #    ).nil?
  #    puts option_parser

  #    puts "Missing options: mandatory options".error
  #    puts "-s/--server, -u/--user, -p/--pass, -f/--from, -t/--to"
  #    puts "-b/--body, -S/--subject\n\n" 
  #   exit!
  # end

  if $opt.dry
    puts " |".green + "                               ".green.underline + "\n |".green
    puts " |".green + " *****".red + " THIS IS A DRY TEST ".green.bold.underline + "*****".red
    puts " |".green + "                               ".green.underline + "\n |".green
    sleep 1
  end

  puts "Setting up connection".info
  puts "Server       : #{$opt.server}".info_h3
  puts "Username     : #{$opt.user}".info_h3
  puts "Password     : #{$opt.pass}".info_h3
  puts "From         : #{$opt.from}".info_h3
  puts "To           : #{$opt.to}".info_h3
  puts "CC           : #{$opt.copy}".info_h3
  puts "BCC          : #{$opt.bcopy}".info_h3
  puts "Subject      : #{$opt.subject}".info_h3
  puts "Body         : #{$opt.body}".info_h3
  puts "Attachements : #{$opt.attachements&.join(', ')}".info_h3

  setup_mail($opt.server.split(":")[0], $opt.server.split(":")[1], $opt.user, $opt.pass, $opt.no_ssl)
  sleep 1

  @mail.subject = $opt.subject
  @mail.from    = $opt.from

  # Read and parse 'to' option
  to_arg = read_arg($opt.to)
  if $opt.csv
    to_mail_lst = to_arg
  else
    to_mail_lst = [str2list(to_arg)].flatten.compact
  end

  # Read and parse 'cc' option
  cp_arg = read_arg($opt.copy)
  if $opt.csv
    cp_mail_lst = cp_arg
  else
    cp_mail_lst = [str2list(cp_arg)].flatten.compact
  end

  # Read and parse 'bcc' option
  bcp_arg = read_arg($opt.bcopy)
  if $opt.csv
    bcp_mail_lst = bcp_arg
  else
    bcp_mail_lst = [str2list(bcp_arg)].flatten.compact
  end

  # Add attachment files
  if !$opt.attachments.empty?
    $opt.attachments.each do |file|
      puts "Adding attachment: '#{file}'".step_done
      @mail.add_file(file) 
    rescue Errno::ENOENT
      puts "Attach file not found: '#{file}'".error
    end
  end


  body_orig   = read_arg($opt.body)
  
  puts "Number of recievers: #{to_mail_lst.flatten.size/3}".info

  if $opt.groups.nil? || !$opt.groups.to_i.positive? || $opt.groups.zero?
    groups = to_mail_lst.each_slice(to_mail_lst.size).to_a
  else
    groups = to_mail_lst.each_slice($opt.groups.to_i).to_a
  end  
  
  puts "#{$opt.groups.to_i} groups, #{groups[0].size}(emails)/group".info_h3

  groups.each_with_index do |group, gi|
    puts "".step_h1 + "Group ##{gi+1}".bold + " | #{Time.new.getlocal.strftime("%Y-%m-%d %H:%M:%S %Z")}"
    group.each_with_index do |email, ei|    
      body = body_orig

      if email.is_a?(Array)      
        fname, lname, mail = email
        next if mail.nil? || mail.empty?        
        puts "First name: #{fname}, Last name: #{lname}, Email: #{mail}".info_h3
        email_named = "#{fname.to_s.capitalize} #{lname.to_s.capitalize} <#{mail.downcase}>"

        puts "#{ei+1}) Sending to ".step_h2 + "'#{email_named}'".bold
        puts "#{"DRY TEST - ".yellow}the email will NOT be actually sent.".warn_h3 if $opt.dry
        build_message(track(body, mail, fname)).to_s
        @mail.to email_named if validate_email(mail)
        email = email_named
      else
        puts "#{"DRY TEST - ".yellow}the email will NOT be actually sent.".warn_h3 if $opt.dry
        puts "#{ei+1}) Sending to ".step_h2 + "'#{email}'".bold
        build_message(track(body, email)).to_s
        @mail.to validate_email(email)
      end

      unless cp_mail_lst.nil? || cp_mail_lst.empty?
        if $opt.csv
          @mail.cc cp_mail_lst.map {|e| "#{e[0].to_s} #{e[1].to_s} <#{e[2].to_s}>"}
        else
          @mail.cc cp_mail_lst
          # track("", email) # why I need to track cc:?
        end
      end
      
      unless bcp_mail_lst.nil? || bcp_mail_lst.empty?
        if $opt.csv
          @mail.bcc bcp_mail_lst.map {|e| "#{e[0].to_s} #{e[1].to_s} <#{e[2].to_s}>"}
        else
          @mail.bcc bcp_mail_lst
          # track("", email) # why I need to track bcc:?
        end
      end

      if !$opt.dry # don't send the email if it's a dry run
        begin
          @mail.deliver
        rescue Net::SMTPSyntaxError => e
          puts "Invalid Email Address".error
          puts "Please carefully review all fields from the following".warn
          puts "From:".info
          pp @mail.from
          puts "To:".info
          pp @mail.to 
          puts "CC:".info
          pp @mail.cc 
          puts "Bcc:".info
          pp @mail.bcc 
          puts "Jumping to the next email in the list".warn
          next
        rescue Net::SMTPAuthenticationError => e
          puts "Authentication Error".error 
          puts "Invalid Email Address / Password, Or The mail server policy is blocking SMTP authentication".error

          puts "For Office365 SMTP AUTH issues:".info 
          puts "Enable SMTP AUTH globally, from powershell:".info
          puts "# Install ExchangeOnline Module".info_h3
          puts "Install-Module -Name ExchangeOnlineManagement".info_h3
          puts "Install-Module -Name PSWSMan # for Linux/Nix (requires running pwsh as sudo)".info_h3
          puts "# Save your credentials (email and pass) in powershell".info_h3
          puts "$UserCredential = Get-Credential".info_h3
          puts "# Load ExchangeOnline Module".info_h3
          puts "Import-Module ExchangeOnlineManagement".info_h3
          puts "# Connect to Office365 using the main admin user".info_h3
          puts "Connect-ExchangeOnline -Credential $UserCredential".info_h3
          puts "# Enable SMTP AUTH Gloabally ".info_h3
          puts "Set-TransportConfig -SmtpClientAuthenticationDisabled $false".info_h3
          puts "# Confirm".info_h3
          puts "Get-TransportConfig | Format-List SmtpClientAuthenticationDisabled".info_h3
        
          puts "Disable security defaults:".info
          puts "1. Go to Asure portal (https://aad.portal.azure.com/) from admin panel (https://admin.microsoft.com/)".info_h3
          puts "2. Select **Properties**".info_h3
          puts "3. Click **Manage Security defaults**".info_h3
          puts "4. Select **No** Under **Enable Security defaults**".info_h3

          puts "Manage user's email apps:".info
          puts "1. From (https://admin.microsoft.com/), go to Users".info_h3
          puts "2. Select your user, a right-side menu opens".info_h3
          puts "3. Click **Mail** tab".info_h3
          puts "4. Select **Manage email apps**".info_h3
          puts "5. Check **Authenticated SMTP**".info_h3
          puts "6. Wait for +10 minutes before sending emails again**".info_h3

          puts "-------------".red
          puts e.full_message
          puts "-------------".red

        rescue Exception => e
          puts e.full_message
          puts e.backtrace_locations
        end        
      end

      puts "  Sent to '#{email}'".step_done
      if $opt.csv
        puts "      └─> cc : #{cp_mail_lst.map {|e| "#{e[0]} #{e[1]} <#{e[2]}>"}.join(', ')}".step_h3  unless cp_mail_lst.nil?  || cp_mail_lst.empty?
        puts "      └─> bcc: #{bcp_mail_lst.map {|e| "#{e[0]} #{e[1]} <#{e[2]}>"}.join(', ')}".step_h3 unless bcp_mail_lst.nil? || bcp_mail_lst.empty?
      else
        puts "      └─> cc : #{cp_mail_lst.join(', ')}".step_h3  unless cp_mail_lst.nil?  || cp_mail_lst.empty?
        puts "      └─> bcc: #{bcp_mail_lst.join(', ')}".step_h3 unless bcp_mail_lst.nil? || bcp_mail_lst.empty?
      end
      @mail.html_part = nil # This is to clear the html_part from the previous body, otherwise the current body will be appended to the previous one
    end
    puts "Delay for #{$opt.delay.to_i} sec".info unless $opt.delay.to_i.zero?
    sleep($opt.delay.to_i) unless group == groups.last  # dont wait after the last group
  end
  
  print_mail_errors
  puts "\n*****".red + " THIS IS A DRY TEST ".green.bold.underline + "*****\n".red if $opt.dry 

rescue OptionParser::MissingArgument => e
  puts option_parser
  e.args.each {|arg| puts '[!] '+ "#{e.reason.capitalize} for '#{arg}' option."}
rescue OptionParser::InvalidOption => e
  puts option_parser
  pp e
rescue Net::SMTPAuthenticationError => e
  puts "Authentication Error".error 
  puts "For Office365 SMTP AUTH issues:".info 
  puts "Enable SMTP AUTH globally, from powershell:".info
  puts "# Install ExchangeOnline Module".info_h3
  puts "Install-Module -Name ExchangeOnlineManagement".info_h3
  puts "Install-Module -Name PSWSMan # for Linux/Nix".info_h3
  puts "# Load ExchangeOnline Module".info_h3
  puts "Import-Module ExchangeOnlineManagement".info_h3
  puts "# Connect to Office365 using the main admin user".info_h3
  puts "Connect-ExchangeOnline -UserPrincipalName admin@YOURCOMPANY.onmicrosoft.com".info_h3
  puts "# Enable SMTP AUTH Gloabally ".info_h3
  puts "Set-TransportConfig -SmtpClientAuthenticationDisabled $false".info_h3
  puts "# Confirm".info_h3
  puts "Get-TransportConfig | Format-List SmtpClientAuthenticationDisabled".info_h3

  puts "Disable security defaults:".info
  puts "1. Go to Asure portal (https://aad.portal.azure.com/) from admin panel (https://admin.microsoft.com/)".info_h3
  puts "2. Select **Properties**".info_h3
  puts "3. Click **Manage Security defaults**".info_h3
  puts "4. Select **No** Under **Enable Security defaults**".info_h3

  puts "-------------".red
  puts e.full_message
  puts "-------------".red
rescue Net::SMTPSyntaxError => e 
  puts e.full_message
rescue Interrupt
  puts 
  puts "Script has been interrupted by user".error
rescue Exception => e
  puts "#{$PROGRAM_NAME} Exception".error
  puts e.full_message
  puts e.backtrace_locations
end
