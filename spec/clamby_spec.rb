require 'spec_helper'
require 'support/shared_context'

describe Clambytoo do
  include_context 'paths'

  before { Clambytoo.configure(Clambytoo::DEFAULT_CONFIG.dup) }

  it "should find clamscan" do
    expect(Clambytoo.scanner_exists?).to be true
  end

  it "should scan file as safe" do
    expect(Clambytoo.safe?(good_path)).to be true
    expect(Clambytoo.virus?(good_path)).to be false
  end

  it "should scan file and return nil" do
    Clambytoo.configure({:error_file_missing => false})
    expect(Clambytoo.safe?(bad_path)).to be nil
    expect(Clambytoo.virus?(bad_path)).to be nil
  end

  it "should scan file as dangerous" do
    begin
      file = download('https://secure.eicar.org/eicar.com')
    rescue SocketError => error
      pending("Skipped because reasons: #{error}")
    end

    dangerous = file.path
    Clambytoo.configure({:error_file_virus => true})
    expect{Clambytoo.safe?(dangerous)}.to raise_exception(Clambytoo::VirusDetected)
    expect{Clambytoo.virus?(dangerous)}.to raise_exception(Clambytoo::VirusDetected)
    Clambytoo.configure({:error_file_virus => false})
    expect(Clambytoo.safe?(dangerous)).to be false
    expect(Clambytoo.virus?(dangerous)).to be true
    File.delete(dangerous)
  end

  # From the clamscan man page:
  # Pass the file descriptor permissions to clamd. This is useful if clamd is
  # running as a different user as it is faster than streaming the file to
  # clamd. Only available if connected to clamd via local(unix) socket.
  context 'fdpass option' do
    it 'is false by default' do
      expect(Clambytoo.config[:fdpass]).to eq false
    end
    it 'accepts an fdpass option in the config' do
      Clambytoo.configure(fdpass: true)
      expect(Clambytoo.config[:fdpass]).to eq true
    end
  end

  # From the clamscan man page:
  # Forces file streaming to clamd. This is generally not needed as clamdscan
  # detects automatically if streaming is required. This option only exists for
  # debugging and testing purposes, in all other cases --fdpass is preferred.
  context 'stream option' do
    it 'is false by default' do
      expect(Clambytoo.config[:stream]).to eq false
    end
    it 'accepts an stream option in the config' do
      Clambytoo.configure(stream: true)
      expect(Clambytoo.config[:stream]).to eq true
    end
  end

  context 'error_clamscan_client_error option' do
    it 'is false by default' do
      expect(Clambytoo.config[:error_clamscan_client_error]).to eq false
    end
    it 'accepts an error_clamscan_client_error option in the config' do
      Clambytoo.configure(error_clamscan_client_error: true)
      expect(Clambytoo.config[:error_clamscan_client_error]).to eq true
    end

    before {
      Clambytoo.configure(check: false)
      allow_any_instance_of(Process::Status).to receive(:exitstatus).and_return(2)
      allow(Clambytoo).to receive(:system)
    }

    context 'when false' do
      before { Clambytoo.configure(error_clamscan_client_error: false) }

      it 'virus? returns true when the daemonized client exits with status 2' do
        Clambytoo.configure(daemonize: true)
        expect(Clambytoo.virus?(good_path)).to eq true
      end
      it 'returns true when the client exits with status 2' do
        Clambytoo.configure(daemonize: false)
        expect(Clambytoo.virus?(good_path)).to eq true
      end
    end

    context 'when true' do
      before { Clambytoo.configure(error_clamscan_client_error: true) }

      it 'virus? raises when the daemonized client exits with status 2' do
        Clambytoo.configure(daemonize: true)
        expect { Clambytoo.virus?(good_path) }.to raise_error(Clambytoo::ClamscanClientError)
      end
      it 'returns true when the client exits with status 2' do
        Clambytoo.configure(daemonize: false)
        expect(Clambytoo.virus?(good_path)).to eq true
      end
    end
  end

  context 'executable paths' do
    context 'executable_path_clamscan option' do
      it 'is clamscan by default' do
        expect(Clambytoo.config[:executable_path_clamscan]).to eq 'clamscan'
      end
      it 'accepts an executable_path_clamscan option in the config' do
        path = '/custom/path/clamscan'
        Clambytoo.configure(executable_path_clamscan: path)
        expect(Clambytoo.config[:executable_path_clamscan]).to eq path
      end
    end

    context 'executable_path_clamdscan option' do
      it 'is clamdscan by default' do
        expect(Clambytoo.config[:executable_path_clamdscan]).to eq 'clamdscan'
      end
      it 'accepts an executable_path_clamdscan option in the config' do
        path = '/custom/path/clamdscan'
        Clambytoo.configure(executable_path_clamdscan: path)
        expect(Clambytoo.config[:executable_path_clamdscan]).to eq path
      end
    end

    context 'executable_path_freshclam option' do
      it 'is freshclam by default' do
        expect(Clambytoo.config[:executable_path_freshclam]).to eq 'freshclam'
      end
      it 'accepts an executable_path_freshclam option in the config' do
        path = '/custom/path/freshclam'
        Clambytoo.configure(executable_path_freshclam: path)
        expect(Clambytoo.config[:executable_path_freshclam]).to eq path
      end
    end
  end
end
