##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class MetasploitModule < Msf::Auxiliary

  # Exploit mixins should be called first
  include Msf::Exploit::Remote::DCERPC

  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'        => 'MS16-047 Badlock Detection',
      'Description' => %q{
        This module can be used to detect if a machine is missing the patch that
        fixes the Badlock vulnerability.
      },
      'Author'      => 'Sean Dillon <sean.dillon@risksense.com>',
      'References'  =>
        [
          [ 'CVE', '2016-0128' ],
          [ 'MSB', 'MS16-047' ],
          [ 'URL', 'https://technet.microsoft.com/en-us/library/security/ms16-047.aspx' ],
          [ 'URL', 'http://badlock.org' ]
        ],
      'License'     => MSF_LICENSE
    )

    deregister_options('RHOST')

    register_options(
      [
        Opt::RPORT(135)
      ], self.class)
  end

  def detect_badlock()
    begin
      op_sam2 = 0x39;
      sam_uuid = '12345778-1234-abcd-ef00-0123456789ac'

      connect

      handle = dcerpc_handle(sam_uuid, '1.0', 'ncacn_np', [datastore['RPORT']])
      dcerpc_bind(handle)

      print_status("Bound to #{sam_uuid}")

      count = (ip.length / 2).chr
      data = ""
      data << "\x00\x02\x00\x00"  # reference_id
      data << count               # max count
      data << "\x00"              # offset
      data << count               # actual count
      data << "\\" + ip           # name
      data << "\x30"              # access mask

      pkt = dcerpc.call(op_sam2, data)
      print(pkt)
      status = ""

      if status == "STATUS_SUCCESS" or status == "STATUS_ACCESS_DENIED"
        print_warning("Host appears to be VULNERABLE to MS16-047 (Badlock)!")
      else
        print_status("Unable to determine if vulnerable, unexpected #{status}")
      end

    rescue ::Rex::Proto::SMB::Exceptions::LoginError
      print_status("Host is NOT vulnerable (or anonymous login failed)")
    rescue ::Rex::Proto::SMB::Exceptions::NoReply, Rex::Proto::DCERPC::Exceptions::NoResponse
      print_status("The DCERPC service did not reply to our request")
    ensure
      disconnect
    end
  end

  # Obtain information about a single host
  def run_host(ip)
    begin
      detect_badlock
    rescue ::Interrupt
      raise $!
    rescue ::Exception => e
      print_error("#{e.class}: #{e.message}")
    end
  end

end
