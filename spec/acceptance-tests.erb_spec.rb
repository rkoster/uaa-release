require 'rspec'
require 'bosh/template/test'
require 'base64'
require 'tmpdir'
require 'yaml'

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

  describe 'config/bpm.yml' do
    let(:template) { job.template('config/bpm.yml') }

    it 'declares no processes by default' do
      expect(YAML.safe_load(template.render({}))['processes']).to eq([])
    end

    it 'declares the softkey plugin and its volume when enabled' do
      # Explicit braces (not a bare trailing hash): on this Ruby/bosh-template
      # gem combination, a bare `render('acceptance_tests' => {...})` is
      # parsed as keyword arguments against Template#render's `spec:`/
      # `consumes:` keyword params and raises ArgumentError. The braces force
      # it to be treated as the single positional properties-hash argument.
      rendered = YAML.safe_load(template.render(
        { 'acceptance_tests' => { 'enable_softkey_remote_signer_plugin' => true } }
      ))
      process = rendered['processes'].first

      expect(process['name']).to eq('softkey-remote-signer')
      expect(process['additional_volumes']).to include(
        'path' => '/var/vcap/sys/run/uaa', 'writable' => true
      )
      expect(process['args']).to include('/var/vcap/sys/run/uaa/remote-signer.sock')
    end
  end

  describe 'monit' do
    # monit is deliberately not registered under the job spec's `templates:`
    # block (BOSH renders it automatically from the job root), so it can't
    # be looked up via job.template like the other templates in this file --
    # Bosh::Template::Test::Job#template only resolves paths registered
    # there. Build the Template directly against the job's spec/monit files
    # instead.
    let(:job_spec_hash) { YAML.safe_load(File.read(File.join(release_path, 'jobs/acceptance-tests/spec'))) }
    let(:template) do
      Bosh::Template::Test::Template.new(
        job_spec_hash,
        File.join(release_path, 'jobs/acceptance-tests/monit')
      )
    end

    it 'supervises nothing by default' do
      expect(template.render({}).strip).to eq('')
    end

    it 'supervises the softkey plugin when enabled' do
      # See the comment on the equivalent config/bpm.yml test above: the
      # explicit braces are required on this Ruby/bosh-template gem
      # combination, not a stylistic choice.
      rendered = template.render(
        { 'acceptance_tests' => { 'enable_softkey_remote_signer_plugin' => true } }
      )
      expect(rendered).to include('check process softkey-remote-signer')
      expect(rendered).to include('bpm start acceptance-tests -p softkey-remote-signer')
    end
  end
end
