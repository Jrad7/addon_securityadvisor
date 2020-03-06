package Cpanel::Security::Advisor::Assessors::Imunify360;

# Copyright (c) 2019, cPanel, L.L.C.
# All rights reserved.
# http://cpanel.net
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of the owner nor the names of its contributors may
#       be used to endorse or promote products derived from this software
#       without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL  BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use strict;
use warnings;
use base 'Cpanel::Security::Advisor::Assessors';

use Cpanel::Config::Sources ();
use Cpanel::Version         ();
use Cpanel::HTTP::Client    ();
use Cpanel::JSON            ();
use Cpanel::SafeRun::Object ();
use Cpanel::Sys::OS::Check  ();
use Cpanel::Sys::GetOS      ();
use Cpanel::Template        ();

use Cpanel::Imports;

our $IMUNIFY360_MINIMUM_CPWHM_VERSION = '11.79';    # we want it usable on both development and release builds for 11.80
our $IMUNIFYAV_MINIMUM_CPWHM_VERSION  = '11.87';

sub version {
    return '2.00';
}

sub generate_advice {
    my ($self) = @_;

    my $cpanel_version = Cpanel::Version::getversionnumber();

    my $rpm = Cpanel::RPM->new();
    $self->{has_clam} = $rpm->has_rpm('cpanel-clamav');

    eval {

        # These checks will only run on v80 and higher
        if (   Cpanel::Version::compare( $cpanel_version, '>=', $IMUNIFY360_MINIMUM_CPWHM_VERSION )
            && require Whostmgr::Imunify360
            && _is_imunify_supported() ) {

            $self->{i360} = {
                data      => Whostmgr::Imunify360::get_imunify360_data(),
                installed => Whostmgr::Imunify360::is_imunify360_installed(),
                licensed  => Whostmgr::Imunify360::is_imunify360_licensed(),
                price     => Whostmgr::Imunify360::get_imunify360_price(),
            };

            if ( !$self->{i360}{data}{disabled} ) {
                $self->_suggest_imunify360;
            }

        }

        # These checks will only run on v88 and highger.
        if (   Cpanel::Version::compare( $cpanel_version, '>=', $IMUNIFYAV_MINIMUM_CPWHM_VERSION )
            && require Whostmgr::Store::Product::ImunifyAVPlus
            && ( !$self->{i360}{installed} || !$self->{i360}{licensed} ) ) {

            my $store = Whostmgr::Store::Product::ImunifyAVPlus->new( redirect_path => 'cgi/securityadvisor/index.cgi' );

            if ( $store->should_offer() ) {

                $self->{iav} = {
                    installed => $store->is_product_installed(),
                    licensed  => $store->is_product_licensed(),
                    price     => $store->get_product_price(),
                };

                $self->_suggest_iav;

            }
        }
    };
    if ( my $exception = $@ ) {
        print STDERR $exception;    # STDERR gets sent to ULC/logs/error_log.
        die $exception;
    }

    return 1;
}

sub _get_purchase_and_install_template {
    return << 'TEMPLATE';
[%- locale.maketext('Use [asis,Imunify360] for a comprehensive suite of protection against attacks on your servers.') %]
    <ul>
        <li>[%- locale.maketext('Multi-layered defense stops attacks with advanced firewall, herd immunity, Intrusion Prevention System, and more.') -%]</li>
        <li>[%- locale.maketext('Powered by AI with advanced detection of brute force attacks, zero-day, and unknown security threats.')-%]</li>
        <li>[%- locale.maketext('[asis,Proactive Defense™] recognizes malicious code in real-time and stops malware in its tracks.') -%]</li>
        <li>[%- locale.maketext('Easy management right inside your [asis,WHM] interface.')-%]</li>
        <li>[%- locale.maketext('Patch Management via [asis,KernelCare] and hardened [asis,PHP]')-%]</li>
        <li><a href="https://go.cpanel.net/buyimunify360" target="_new">[%- locale.maketext('Learn more about [asis,Imunify360]')%]</a></li>
    </ul>
[%- data.link -%]
TEMPLATE
}

sub _get_purchase_template {
    return << 'TEMPLATE';
<style>
#Imunify360_update_license blockquote {
    margin:0
}
</style>
<ul>
    <li>
    [%- data.link -%]
    </li>
    <li>
    [%- locale.maketext(
        'To uninstall [asis,Imunify360], read the [output,url,_1,Imunify360 Documentation,_2,_3].',
        'https://go.cpanel.net/imunify360uninstall',
        'target',
        '_blank',
    ) -%]
    </li>
</ul>
TEMPLATE
}

sub _get_install_template {
    return << 'TEMPLATE';
[%- locale.maketext(
        '[output,url,_1,Install Imunify360,_2,_3].',
        data.path,
        'target',
        '_parent'
) -%]
TEMPLATE
}

sub _process_template {
    my ( $template_ref, $args )   = @_;
    my ( $ok,           $output ) = Cpanel::Template::process_template(
        'whostmgr',
        {
            'template_file' => $template_ref,
            'data'          => $args,
        }
    );
    return $output if $ok;
    die "Template processing failed: $output";
}

sub _get_script_number() {
    my $current_version = Cpanel::Version::getversionnumber();
    my $is_v84_or_older = Cpanel::Version::compare( $current_version, '>=', '11.83' );

    return $is_v84_or_older ? 'scripts13' : 'scripts12';
}

sub create_purchase_link {
    my ($self) = @_;

    my $installed = $self->{i360}{installed};
    my $price     = $self->{i360}{price};

    my $custom_url;
    if ( Cpanel::Version::compare( Cpanel::Version::getversionnumber(), '>=', '11.81' ) ) {
        my $imunify360 = Whostmgr::Imunify360->new;
        $custom_url = $imunify360->get_custom_url();
    }

    my $cp_url = $self->base_path( _get_script_number() . '/purchase_imunify360_init' );

    if ($custom_url) {
        return locale()->maketext( '[output,url,_1,Get Imunify360,_2,_3].', $custom_url, 'target', '_blank', );
    }
    if ($installed) {
        return locale()->maketext( 'To purchase a license, visit the [output,url,_1,cPanel Store,_2,_3].', $cp_url, 'target', '_parent', );
    }
    if ($price) {
        return locale()->maketext( '[output,url,_1,Get Imunify360,_2,_3] for $[_4]/month.', $cp_url, 'target', '_parent', $price );
    }
    return locale()->maketext( '[output,url,_1,Get Imunify360,_2,_3].', $cp_url, 'target', '_parent', );
}

sub _suggest_imunify360 {
    my ($self) = @_;

    my $is_kernelcare_needed = _needs_kernelcare();
    my $link                 = $self->create_purchase_link();

    if ( !$self->{i360}{licensed} && $self->{i360}{installed} ) {
        my $output = _process_template(
            \_get_purchase_template(),
            {
                'link' => $link,
            },
        );

        $self->add_info_advice(
            key          => 'Imunify360_update_license',
            text         => locale()->maketext('[asis,Imunify360] is installed but you do not have a current license.'),
            suggestion   => $$output,
            block_notify => 1,                                                                                             # Do not send a notification about this
        );
    }
    elsif ( !$self->{i360}{licensed} && !$self->{i360}{installed} ) {

        my $output = _process_template(
            \_get_purchase_and_install_template(),
            {
                'link'               => $link,
                'include_kernelcare' => $is_kernelcare_needed,
            },
        );

        $self->add_info_advice(
            key          => 'Imunify360_purchase',
            text         => locale()->maketext('Use [asis,Imunify360] for complete protection against attacks on your servers.'),
            suggestion   => $$output,
            block_notify => 1,                                                                                                      # Do not send a notification about this
        );
    }
    elsif ( !$self->{i360}{installed} ) {
        my $output = _process_template(
            \_get_install_template(),
            {
                'path'               => $self->base_path( _get_script_number . '/install_imunify360' ),
                'include_kernelcare' => $is_kernelcare_needed,
            }
        );

        $self->add_info_advice(
            key          => 'Imunify360_install',
            text         => locale()->maketext('You have an [asis,Imunify360] license, but you do not have [asis,Imunify360] installed on your server.'),
            suggestion   => $$output,
            block_notify => 1,                                                                                                                              # Do not send a notification about this
        );
    }
    else {
        my $imunify_whm_link = locale()->maketext(
            '[output,url,_1,Open Imunify360,_2,_3].',
            $self->base_path('/cgi/imunify/handlers/index.cgi'),
            'target' => '_parent'
        );

        $self->add_good_advice(
            key        => 'Imunify360_present',
            text       => locale()->maketext(q{Your server is protected by [asis,Imunify360].}),
            suggestion => locale()->maketext(
                q{For help getting started, read [output,url,_1,Imunify360’s documentation,_2,_3].},
                'https://go.cpanel.net/imunify360gettingstarted',
                'target' => '_blank',
              )
              . '<br><br>'
              . $imunify_whm_link,
            block_notify => 1,    # Do not send a notification about this
        );
    }

    return 1;
}

sub _suggest_iav {
    my ($self) = @_;

    if ( !$self->{iav}{installed} && !$self->{iav}{licensed} ) {
        $self->_avplus_advice( action => 'installav', advice => 'bad' );
        $self->_avplus_advice( action => 'upgrade',   advice => 'info' );
    }
    elsif ( !$self->{iav}{installed} && $self->{iav}{licensed} ) {
        $self->_avplus_advice( action => 'installplus', advice => 'bad' );
    }
    elsif ( $self->{iav}{installed} && !$self->{iav}{licensed} ) {
        $self->_avplus_advice( action => 'upgrade', advice => 'info' );
    }
    elsif ( $self->{iav}{installed} && $self->{iav}{licensed} ) {
        $self->add_good_advice(
            key          => 'ImunifyAV+_present',
            text         => locale()->maketext(q{Your server is protected by [asis,ImunifyAV+].}),
            block_notify => 1,
        );
    }

    if ( $self->{has_clam} && $self->{iav}{installed} ) {
        my $plugins_url = $self->base_path('scripts2/manage_plugins');
        $self->add_warn_advice(
            'key'          => 'ImunifyAV+_clam_and_iav_installed',
            'block_notify' => 1,
            'text'         => locale()->maketext("Uninstall [asis,ClamAV]."),
            'suggestion'   => locale()->maketext( "[asis,ClamAV] and [asis,ImunifyAV] are both installed. [output,url,_1,Uninstall ClamAV,_2,_3]", $plugins_url, 'target', '_blank' ),
        );
    }

    return 1;
}

sub _upgrade_avplus_text {
    my ($self) = @_;
    my $purchase_url = $self->base_path('scripts13/purchase_imunifyavplus_init_SECURITYADVISOR');
    return {
        text       => locale()->maketext("Use [asis,ImunifyAV+] to scan for malware and clean up infected files with one click."),
        link       => locale()->maketext( "[output,url,_1,Get ImunifyAV+,_2,_3] for \$[_4]/month.", $purchase_url, 'target', '_blank', $self->{iav}{price} ),
        suggestion => locale()->maketext("ImunifyAV+ brings you the advanced scanning of ImunifyAV and adds more options to make protecting servers from malicious code almost effortless. Enhanced features include:") . "<ul>" . "<li>"
          . locale()->maketext("Malware and virus scanning") . "</li>" . "<li>"
          . locale()->maketext("Automatic clean up") . "</li>" . "<li>"
          . locale()->maketext( "[output,url,_1,Learn more about ImunifyAV+,_2,_3]", 'https://go.cpanel.net/buyimunifyAVplus', 'target', '_blank' ) . "</li>" . "</ul>",
    };
}

sub _install_av_text {
    my ($self) = @_;
    my $install_av_url = $self->base_path('scripts13/install_imunifyav_SECURITYADVISOR');
    return {
        text       => locale()->maketext("Install [asis,ImunifyAV] to scan your websites for malware."),
        link       => locale()->maketext( "[output,url,_1,Install ImunifyAV,_2,_3] for free.", $install_av_url, 'target', '_blank' ),
        suggestion => '',
    };
}

sub _install_avplus_text {
    my ($self) = @_;
    my $install_plus_url = $self->base_path('scripts13/install_imunifyavplus_SECURITYADVISOR');
    return {
        text       => locale()->maketext("You have an [asis,ImunifyAV+] license, but you do not have [asis,ImunifyAV+] installed on your server."),
        link       => locale()->maketext( "[output,url,_1,Install ImunifyAV+,_2,_3].", $install_plus_url, 'target', '_blank' ),
        suggestion => '',
    };
}

sub _avplus_advice {
    my ( $self, %args ) = @_;

    my $content = {};

    if ( $args{action} eq 'upgrade' ) {
        $content = $self->_upgrade_avplus_text();
    }
    elsif ( $args{action} eq 'installav' ) {
        $content = $self->_install_av_text();
    }
    elsif ( $args{action} eq 'installplus' ) {
        $content = $self->_install_avplus_text();
    }
    else {
        return 0;
    }

    my %advice = (
        'key'          => "ImunifyAV+_$args{advice}",
        'block_notify' => 1,
        'text'         => $content->{text},
        'suggestion'   => $content->{suggestion} . $content->{link},
    );

    my $method = "add_$args{advice}_advice";
    return $self->$method(%advice);
}

sub _is_imunify_supported {

    my $centos_version = Cpanel::Sys::OS::Check::get_strict_centos_version();
    my $os             = Cpanel::Sys::GetOS::getos();
    my $os_ok          = ( ( $os =~ /^centos$/ && ( $centos_version == 6 || $centos_version == 7 ) ) || $os =~ /^cloudlinux$/i );
    return $os_ok;
}

sub _needs_kernelcare {
    my $centos_version = Cpanel::Sys::OS::Check::get_strict_centos_version();

    # This is only needed on CentOS 6 and 7. CloudLinux already has symlink protection built in,
    # and other distros (RHEL, Amazon Linux, etc.) are not supported.
    return 0 if not defined $centos_version or ( $centos_version != 6 and $centos_version != 7 );

    # It doesn't make sense to attempt to manage the kernel of a container from within the container.
    return 0 if _server_type() eq 'container';

    # Partners may disable KernelCare availability via Manage2
    return 0 if Whostmgr::Imunify360::get_kernelcare_data()->{'disabled'};

    return 1;
}

sub _server_type {
    my ($self) = @_;

    my $run = Cpanel::SafeRun::Object->new_or_die(
        program => '/usr/local/cpanel/bin/envtype',
    );
    chomp( my $server_type = $run->stdout );

    return 'standard' if $server_type eq 'standard';

    return 'container' if grep { $server_type eq $_ } qw(
      virtuozzo
      vzcontainer
      virtualiron
      lxc
      vserver
    );

    return 'vm';
}

1;
