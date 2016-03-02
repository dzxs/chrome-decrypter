#!/usr/bin/env ruby
=begin
在chrome2keepass基础上添加解密功能
chrome2:https://github.com/alanpca/chrome2keepass.git
=end

begin
  require 'optparse'
  require 'ostruct'
  require 'sqlite3'
  require 'cgi'
  require 'builder'
rescue LoadError => e
  puts "You don't have a required gem: " + e.message.split[-1]
  exit
end

require './lib/dpapi.rb'
include DpApi

def get_title(entry)
  # This is here for future support of renaming
  title = CGI.escapeHTML(entry['origin_url'])
end

# Put the entry to $stdout based on the Keepass XML formatting
def put_entry(xml, entry)
  # Chrome seems to have put a bunch of no user/pass logins in my DB, which are quite
  # useless, so we just ignore them and return back to the next row.
  return if entry['username_value'] == '' && entry['password_value'] = ''

  # The datestring that Keepass likes
  datestring = Time.now.strftime('%Y-%m-%dT%H:%M:%S')

  # The 'meat' of the entry
  xml.entry {
    xml.title get_title(entry)
    xml.username CGI.escapeHTML(entry['username_value'])
    xml.password CGI.escapeHTML(entry['password_value'])
    xml.url CGI.escapeHTML(entry['origin_url'])
    xml.comment ""
    xml.icon '1'
    xml.creation datestring
    xml.lastaccess datestring
    xml.lastmod datestring
    xml.expire 'Never'
  }
end

def getoptions(args)
  options = OpenStruct.new
  # Default values
  options.location = ENV['HOME'] + '\\AppData\\Local\\Google\\Chrome\\User Data\\'
  options.profile = 'Default'
  options.show_help = false
  options.enable_decrypt = false

  opts = OptionParser.new do |opts|
    opts.banner = 'Usage: chrome2keepass [options]'
    opts.separator ''
    opts.on('-p', '--profile [PROFILE]', 'Name of Chrome Profile',
            "Default: 'Default'") do |profile|
      options.profile = profile
    end

    opts.on('-l', '--location [LOCATION]', 'Location to chrome config',
            "Default: '$HOME/.config/chromium'") do |location|
      options.location = location
    end

    opts.on('-e', '--exact [LOCATION]', 'Exact path to Chrome password database',
            'Typically used with backup copy') do |filename|
      options.exactfile = filename
    end

    opts.on('-f', '--filename [FILENAME]', 'Filename to use instead of STDOUT') do |filename|
      options.filename = filename
    end

    opts.on('-d', '--decrypt', 'decrypt the password') do |enable_decrypt|
      options.enable_decrypt = true
    end
    opts.on('-h', '--help', 'Show this help') do |helpme|
      options.show_help = true
    end
  end
  others = Array.new
  # Loop through each argument and parse it.
  args.each do |arg|
    begin
      opts.parse!
    rescue OptionParser::InvalidOption => e
      others.push e.args[0]
    end
  end
  # Return a hash with the data we may need.
  # @options are the options that were set by arguments
  # @others are the bad options
  # @usage is the usage help
  {'options' => options, 'others' => others, 'usage' => opts}
end

values = getoptions(ARGV)
options = values['options']

if options.show_help
  # If we get sent the help options, show help and exit
  puts values['usage']
  exit
end
if values['others'].size > 0
  # We got some bad arguments, let the user know
  print 'Bad arguments: '
  values['others'].each { |badopt| print badopt }
  exit
else

  output = $stdout
  if !options.filename.nil?
    if !File.exist?(options.filename)
      begin
        output = File.new(options.filename, 'w')
      rescue Errno::EACCES
        puts "ERROR: Couldn't open file '" + options.filename + "'"
        exit
      end
    else
      puts "ERROR: File '" + options.filename + "' already exists."
      exit
    end
  end

  # Set the location of the DB based on options sent by user
  if options.exactfile.nil?
    sqdb = options.location + '/' + options.profile + '/Login Data'
  else
    sqdb = options.exactfile
  end

  if !File.exist?(sqdb)
    puts 'Cannot open the database at location: ' + sqdb
    exit
  end

  db = SQLite3::Database.new(sqdb)
  # Give the results as a hash
  db.results_as_hash = true
  begin
    rows = db.execute('SELECT * FROM `logins`')
      # Leave on Exception
  rescue SQLite3::SQLException
    puts 'There is a problem with your Chrome password database'
    exit
  rescue SQLite3::BusyException
    puts 'The Chrome database has been locked, please exit Chrome and try again'
    exit
  end

  xml = Builder::XmlMarkup.new(:target => output, :indent => 2)
  xml.declare! :DOCTYPE, :KEEPASSX_DATABASE

  xml.database {
    xml.group {
      xml.title 'chrome2keepass'
      xml.icon '1'
      rows.each do |entry|
        # Cycle through each entry and print it out
        puts options.enable_decrypt
        if options.enable_decrypt
          plaintext, desc = DpApi.decrypt entry['password_value']
          entry['password_value'] = plaintext
        end

        put_entry(xml, entry)
      end
    }
  }

end
