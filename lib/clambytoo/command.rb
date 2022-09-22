module Clambytoo
  # Interface with the system. Builds and runs the command.
  class Command
    EXECUTABLES = %w(clamscan clamdscan freshclam)

    # Array containing the complete command line.
    attr_accessor :command

    # Returns the appropriate scan executable, based on clamd being used.
    def self.scan_executable
      return 'clamdscan' if Clambytoo.config[:daemonize]
      return 'clamscan'
    end

    # Perform a ClamAV scan on the given path.
    def self.scan(path)
      return nil unless file_exists?(path)

      args = [Shellwords.escape(path), '--no-summary']

      if Clambytoo.config[:daemonize]
        args << '--fdpass' if Clambytoo.config[:fdpass]
        args << '--stream' if Clambytoo.config[:stream]
      end

      args << "-d #{Clambytoo.config[:datadir]}" if Clambytoo.config[:datadir]

      new.run scan_executable, *args


      # $CHILD_STATUS maybe nil if the execution itself (not the client process)
      # fails
      case $CHILD_STATUS && $CHILD_STATUS.exitstatus
      when 0
        return false
      when nil, 2
        # clamdscan returns 2 whenever error other than a detection happens
        if Clambytoo.config[:error_clamscan_client_error] && Clambytoo.config[:daemonize]
          raise Clambytoo::ClamscanClientError.new("Clamscan client error")
        end

        # returns true to maintain legacy behavior
        return true
      else
        return true unless Clambytoo.config[:error_file_virus]

        raise Clambytoo::VirusDetected.new("VIRUS DETECTED on #{Time.now}: #{path}")
      end
    end

    # Update the virus definitions.
    def self.freshclam
      args = []
      args << "--datadir=#{Clambytoo.config[:datadir]}" if Clambytoo.config[:datadir]
      new.run 'freshclam', *args
    end

    # Show the ClamAV version. Also acts as a quick check if ClamAV functions.
    def self.clamscan_version
      new.run scan_executable, '--version'
    end

    # Run the given commands via a system call.
    # The executable must be one of the permitted ClamAV executables.
    # The arguments will be combined with default arguments if needed.
    # The arguments are sorted alphabetically before being passed to the system.
    #
    # Examples:
    #   run('clamscan', file, '--verbose')
    #   run('clamscan', '-V')
    def run(executable, *args)
      executable_full = executable_path(executable)
      self.command = args | default_args
      self.command = command.sort.unshift(executable_full)
      if caller_locations(1,1)[0].label == "clamscan_version"
        Open3.popen3(self.command.join(' ')) do |stdin, stdout, stderr, wait_thr|
          exit_status = wait_thr.value
          return true if exit_status.success? && stderr.gets.nil?
          return nil unless stderr.gets.nil?  #if we have any kind of error executing a command we should return nil
        end
      else
        system(self.command.join(' '), system_options)
      end
    end

    private

    def default_args
      args = []
      args << "--config-file=#{Clambytoo.config[:config_file]}" if Clambytoo.config[:daemonize] && Clambytoo.config[:config_file]
      args << '--quiet' if Clambytoo.config[:output_level] == 'low'
      args << '--verbose' if Clambytoo.config[:output_level] == 'high'
      args
    end

    # This applies to the `system` call itself; does not end up in the command.
    def system_options
      if Clambytoo.config[:output_level] == 'off'
        { out: File::NULL }
      else
        {}
      end
    end

    def executable_path(executable)
      raise "`#{executable}` is not permitted" unless EXECUTABLES.include?(executable)
      Clambytoo.config[:"executable_path_#{executable}"]
    end

    def self.file_exists?(path)
      return true if File.file?(path)

      if Clambytoo.config[:error_file_missing]
        raise Clambytoo::FileNotFound.new("File not found: #{path}")
      else
        puts "FILE NOT FOUND on #{Time.now}: #{path}"
        return false
      end
    end
  end
end
