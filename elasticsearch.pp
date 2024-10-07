# This class managed the elasticsearch component of axa_logboard
#
class axa_logboard::elasticsearch (
  String $ensure              = pick($axa_logboard::version,'present'),
  String $package_name        = 'elasticsearch',
  String $service_name        = 'elasticsearch',
  String $conf_path           = '/etc/elasticsearch/elasticsearch.yml',
  String $conf_template       = 'axa_logboard/elasticsearch/elasticsearch.yml.epp',
  String $log_options_path     = '/etc/elasticsearch/log4j2.properties',
  String $log_options_template = 'axa_logboard/elasticsearch/log4j2.properties.epp',
  Boolean $user_manage        = true,
  Hash $user_params           = {},
  String $user_name           = 'elasticsearch',
  Boolean $dirs_manage        = true,
  String $data_dir            = '/data',
  Boolean $configure_xpack    = true,
  Boolean $configure_sources  = false,
  Boolean $is_monitor         = pick($axa_logboard::is_monitor, false),
  Boolean $is_be              = pick($axa_logboard::is_be, false),
  Boolean $initial_setup      = false,
  String $sudoers_ensure      = 'present',
  String $sudoers_source      = 'puppet:///modules/axa_logboard/elasticsearch/sudoers',
  Hash $plugins               = {},
) {
  $service_enable = $ensure ? {
    'absent' => false,
    default  => true,
  }
  $service_ensure = $ensure ? {
    'absent' => 'stopped',
    default  => 'running',
  }
  $file_ensure = $ensure ? {
    'absent' => 'absent',
    default  => 'file',
  }
  $dir_ensure = $ensure ? {
    'absent' => 'absent',
    default  => 'directory',
  }
  $user_ensure = $ensure ? {
    'absent' => 'absent',
    default  => 'present',
  }

  if $dirs_manage {
    file { $data_dir:
      ensure => $dir_ensure,
      owner  => $user_name,
      group  => $user_name,
    }
  }
  package { $package_name:
    ensure          => $ensure,
    install_options => [
      { '--enablerepo' => 'P_HOMEBREW_DIS' },
    ],
  }

  service { $service_name:
    ensure => $service_ensure,
    enable => $service_enable,
  }

  $default_options = {
    'network.host'         => $facts['networking']['ip'],
    'discovery.seed.hosts' => [],
    'configure_xpack'      => $configure_xpack,
    'initial_setup'        => $initial_setup,
  }
  if $is_monitor {
    $conf_options = lookup('axa_logboard::elasticsearch::options_monitor', Hash, 'deep', {})
  } elsif $is_be {
    $conf_options = lookup('axa_logboard::elasticsearch::options_be', Hash, 'deep', {})
  } else {
    $conf_options = getvar('facts.axapatchenvironment') ? {
      'production' => lookup('axa_logboard::elasticsearch::options_production', Hash, 'deep', {}),
      default      => lookup('axa_logboard::elasticsearch::options_preproduction', Hash, 'deep', {}),
    }
  }
  $options = deep_merge($default_options,$conf_options)

  file { $conf_path:
    ensure  => $file_ensure,
    content => epp($conf_template, { options => $options }),
    owner   => 'root',
    group   => 'root',
    mode    => '0644',
    require => Package[$package_name],
    notify  => Service[$service_name],
  }

  if $configure_xpack {
    $private_key_source = $configure_sources ? {
      true  => 'file:///etc/pki/tls/private/localhost.key',
      false => undef,
    }
    file { '/etc/elasticsearch/certs/privateKey_elasticsearch.pem':
      ensure  => $file_ensure,
      source  => $private_key_source,
      owner   => $user_name,
      group   => $user_name,
      mode    => '0600',
      require => Package[$package_name],
      notify  => Service[$service_name],
    }
    $public_cert_source = $configure_sources ? {
      true  => "puppet:///modules/axa_logboard/certificates/${facts['networking']['hostname']}/elastic.pem.cer",
      false => undef,
    }
    file { '/etc/elasticsearch/certs/elasticsearch.pem.cer':
      ensure  => $file_ensure,
      source  => $public_cert_source,
      owner   => $user_name,
      group   => $user_name,
      mode    => '0644',
      require => Package[$package_name],
      notify  => Service[$service_name],
    }
    $ca_cert_source = $configure_sources ? {
      true  => "puppet:///modules/axa_logboard/certificates/${facts['networking']['hostname']}/elastic.chain.pem",
      false => undef,
    }
    file { '/etc/elasticsearch/certs/elasticsearch.chain.pem':
      ensure  => $file_ensure,
      source  => $ca_cert_source,
      owner   => $user_name,
      group   => $user_name,
      mode    => '0644',
      require => Package[$package_name],
      notify  => Service[$service_name],
    }

    file { '/etc/elasticsearch/saml':
      ensure  => $dir_ensure,
      owner   => $user_name,
      group   => $user_name,
      mode    => '0755',
      require => Package[$package_name],
      notify  => Service[$service_name],
    }

    $idp_metadata_source = $configure_sources ? {
      true  => 'puppet:///modules/axa_logboard/PRD_idp_axacom__sp_logboardMetadata.xml',
      false => undef,
    }
    file { $options['idp.metadata.path']:
      ensure  => $file_ensure,
      source  => $idp_metadata_source,
      owner   => 'root',
      group   => 'root',
      mode    => '0644',
      require => Package[$package_name],
      notify  => Service[$service_name],
    }
  }

  $limits_content = @("EOF")
    elastic  -  nofile  65535
    elastic  -  nproc   4096
    elastic  soft  memlock   unlimited
    elastic  hard  memlock   unlimited
    |-EOF

  file { '/etc/security/limits.d/elasticsearch.conf':
    ensure  => $file_ensure,
    content => $limits_content,
    owner   => 'root',
    group   => 'root',
    mode    => '0644',
    require => Package[$package_name],
    notify  => Service[$service_name],
  }

  $sysctl_content = @("EOF")
    vm.max_map_count=262144
    vm.swappiness=1
    |-EOF

  file { '/etc/sysctl.d/elasticsearch.conf':
    ensure  => $file_ensure,
    content => $sysctl_content,
    owner   => 'root',
    group   => 'root',
    mode    => '0644',
    require => Package[$package_name],
    notify  => Service[$service_name],
  }



  file { $log_options_path:
    ensure  => $file_ensure,
    content => epp($log_options_template, { options => $options }),
    owner   => 'root',
    group   => 'root',
    mode    => '0644',
    require => Package[$package_name],
    notify  => Service[$service_name],
  }

  if $user_manage {
    $user_defaults = {
      ensure           => $user_ensure,
      name             => $user_name,
      comment          => 'elasticsearch user',
      forcelocal       => true,
      managehome       => true,
      expiry           => absent,
      password_min_age => 0,
    }
    user { $user_name :
      * => $user_defaults + $user_params,
    }
  }

  file { '/etc/sudoers.d/elasticsearch':
    ensure       => $sudoers_ensure,
    source       => $sudoers_source,
    owner        => 'root',
    group        => 'root',
    mode         => '0440',
    validate_cmd => '/usr/sbin/visudo -c %',
  }

  $plugins.each |$k,$v| {
    axa_logboard::elasticsearch::plugin { $k:
      * => $v,
    }
  }
}
