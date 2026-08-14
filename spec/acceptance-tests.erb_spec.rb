require 'rspec'
require 'bosh/template/test'
require 'base64'
require 'tmpdir'

describe 'acceptance-tests job' do
  let(:release_path) { File.join(File.dirname(__FILE__), '..') }
  let(:release) { Bosh::Template::Test::ReleaseDir.new(release_path) }
  let(:job) { release.job('acceptance-tests') }

  describe 'bin/run' do
    let(:template) { job.template('bin/run') }

    # Renders the template and executes it for real (not just substring
    # matching on the unexecuted text), so these specs actually exercise
    # run.erb's require_property guard rather than the surrounding
    # heredocs/exports that happen to mention the same property names.
    def render_and_run(properties)
      rendered = template.render(properties)
      script_path = File.join(Dir.mktmpdir, 'run')
      File.write(script_path, rendered)
      File.chmod(0o755, script_path)

      output = `#{script_path} 2>&1`
      [output, $?.exitstatus]
    end

    let(:all_required_properties) do
      {
        'bosh' => {
          'environment' => 'https://10.0.0.6:25555',
          'client' => 'admin',
          'client_secret' => 'secret',
          'ca_cert' => "-----BEGIN CERTIFICATE-----\nfakecert\n-----END CERTIFICATE-----",
          'deployment' => 'uaa',
        },
        'uaa_deployment_manifest_b64' => Base64.strict_encode64('name: uaa'),
      }
    end

    it 'renders with no properties at all, so the job can be colocated' do
      expect { template.render({}) }.not_to raise_error
    end

    it 'fails at invocation when the director environment is missing' do
      output, exit_status = render_and_run({})

      expect(exit_status).not_to eq(0)
      # This is the require_property guard's own message, not the
      # unconditional "export BOSH_ENVIRONMENT=..." line further down in
      # the script -- the guard runs and exits before that line is ever
      # reached, so this only passes if the guard itself fired.
      expect(output).to include('requires the bosh.environment property to be set')
    end

    it 'does not fail on the property guard when all required properties are set' do
      output, _exit_status = render_and_run(all_required_properties)

      # The script still fails past this point in a test environment
      # (it goes on to mkdir/exec real BOSH-VM paths that don't exist
      # here), so we can't assert a clean exit. What we CAN assert is
      # that none of the require_property guards fired for the
      # properties we supplied.
      expect(output).not_to include('property to be set')
    end
  end
end
