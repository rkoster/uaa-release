require 'rspec'
require 'yaml'
require 'bosh/template/test'

describe 'bpm.yml.erb' do
  let(:release_path) { File.join(File.dirname(__FILE__), '..') }
  let(:release) { Bosh::Template::Test::ReleaseDir.new(release_path) }
  let(:job) { release.job('uaa') }
  let(:template) { job.template('config/bpm.yml') }
  let(:manifest) { YAML.load_file(File.join(File.dirname(__FILE__), 'input/all-properties-set.yml')) }
  let(:rendered) { YAML.safe_load(template.render(manifest['properties'])) }
  let(:uaa_process) { rendered['processes'].find { |p| p['name'] == 'uaa' } }

  it 'mounts the shared remote signer socket directory' do
    expect(uaa_process['additional_volumes']).to include(
      'path' => '/var/vcap/sys/run/uaa',
      'writable' => true
    )
  end

  it 'keeps the ephemeral disk mount' do
    expect(uaa_process['ephemeral_disk']).to be true
  end
end
